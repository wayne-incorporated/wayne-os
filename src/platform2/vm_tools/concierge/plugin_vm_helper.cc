// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/plugin_vm_helper.h"

#include <sys/mount.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/logging.h>
#include <base/values.h>
#include <chromeos/scoped_minijail.h>
#include <dbus/object_proxy.h>

#include "vm_tools/concierge/plugin_vm_config.h"
#include "vm_tools/concierge/vmplugin_dispatcher_interface.h"

namespace vm_tools {
namespace concierge {
namespace pvm {
namespace helper {
namespace {

// Minimal set of devices needed by the helpers.
constexpr const char* kDeviceNames[] = {"full", "null", "urandom", "zero"};

ScopedMinijail SetupSandbox(const base::FilePath& policy_file) {
  ScopedMinijail jail(minijail_new());
  if (!jail) {
    LOG(ERROR) << "Unable to create minijail";
    return ScopedMinijail();
  }

  minijail_namespace_pids(jail.get());
  minijail_namespace_user(jail.get());
  minijail_namespace_vfs(jail.get());
  minijail_namespace_ipc(jail.get());
  minijail_namespace_net(jail.get());
  minijail_namespace_cgroups(jail.get());
  minijail_namespace_uts(jail.get());

  std::string uid_map = base::StringPrintf("0 %d 1", geteuid());
  std::string gid_map = base::StringPrintf("0 %d 1", getegid());
  minijail_uidmap(jail.get(), uid_map.c_str());
  minijail_gidmap(jail.get(), gid_map.c_str());

  // Use a seccomp filter.
  minijail_log_seccomp_filter_failures(jail.get());
  minijail_parse_seccomp_filters(jail.get(), policy_file.value().c_str());
  minijail_use_seccomp_filter(jail.get());

  // We will manage this process's lifetime.
  minijail_run_as_init(jail.get());

  // The helpers do not require any capabilities.
  minijail_no_new_privs(jail.get());
  minijail_use_caps(jail.get(), 0);

  if (minijail_enter_pivot_root(jail.get(), "/mnt/empty") < 0) {
    LOG(ERROR) << "Failed to pivot root to /mnt/empty";
    return ScopedMinijail();
  }

  // Set up minimal set of mounts for the helpers to run.
  if (minijail_mount_with_data(jail.get(), "none", "/", "tmpfs",
                               MS_NOSUID | MS_NODEV | MS_NOEXEC,
                               "size=67108864") < 0) {
    LOG(ERROR) << "Failed to mount root tmpfs";
    return ScopedMinijail();
  }

  if (minijail_bind(jail.get(), kApplicationDir, kApplicationDir, 0)) {
    LOG(ERROR) << "Failed to bind-mount " << kApplicationDir;
    return ScopedMinijail();
  }

  if (minijail_bind(jail.get(), kRuntimeDir, kRuntimeDir, 1)) {
    LOG(ERROR) << "Failed to bind-mount " << kRuntimeDir;
    return ScopedMinijail();
  }

  // Create a minimal /dev with a very restricted set of device nodes.
  // We can't use minijail_mount_dev() because Chrome OS LSM module
  // does not allow unprivileged users mount filesystems other than
  // tmpfs.
  for (auto dev : kDeviceNames) {
    base::FilePath path(base::FilePath("/dev").Append(dev));
    if (minijail_bind(jail.get(), path.value().c_str(), path.value().c_str(),
                      true /* writeable */) < 0) {
      LOG(ERROR) << "Failed to bind-mount " << path.value();
      return ScopedMinijail();
    }
  }

  // Close all file descriptors we may have.
  minijail_close_open_fds(jail.get());

  return jail;
}

bool ConsumeFileDescriptor(int fd, std::string* contents) {
  base::FilePath path(base::StringPrintf("/proc/self/fd/%d", fd));
  return base::ReadFileToString(path, contents);
}

bool ExecutePvmHelper(const std::string& owner_id,
                      std::vector<std::string> params,
                      std::string* stdout_str = nullptr,
                      std::string* stderr_str = nullptr) {
  const base::FilePath path_prefix(kApplicationDir);
  ScopedMinijail jail = SetupSandbox(path_prefix.Append(kPolicyPath));
  if (!jail)
    return false;

  std::vector<std::string> args;
  args.emplace_back(path_prefix.Append(kCommand).value());
  for (auto& param : params)
    args.emplace_back(std::move(param));
  args.emplace_back("--socket-path");
  args.emplace_back(dispatcher::kSocketPath);
  args.emplace_back("--user-identity");
  args.emplace_back(owner_id);

  // Convert args to array of pointers. Must be nullptr terminated.
  std::vector<char*> args_ptr;
  for (const auto& arg : args)
    args_ptr.emplace_back(const_cast<char*>(arg.c_str()));
  args_ptr.emplace_back(nullptr);

  pid_t pid = -1;
  int child_stdout = -1, child_stderr = -1;
  int ret =
      minijail_run_pid_pipes(jail.get(), args_ptr[0], args_ptr.data(), &pid,
                             nullptr, stdout_str ? &child_stdout : nullptr,
                             stderr_str ? &child_stderr : nullptr);
  if (ret != 0) {
    LOG(ERROR) << "failed to execute helper in minijail: " << ret;
    return false;
  }

  if (stdout_str) {
    if (child_stdout >= 0) {
      ConsumeFileDescriptor(child_stdout, stdout_str);
      close(child_stdout);
    }
  }

  if (stderr_str) {
    if (child_stderr >= 0) {
      ConsumeFileDescriptor(child_stderr, stderr_str);
      close(child_stderr);
    }
  }

  // Always call minijail_wait(), otherwise exit code is never
  // queried and the process is left dangling.
  int exit_code = minijail_wait(jail.get());
  jail.reset();

  switch (exit_code) {
    case 0:
      return true;

    case MINIJAIL_ERR_JAIL:
      LOG(ERROR) << "helper failed because seccomp blocked a system call";
      return false;

    default:
      LOG(ERROR) << "helper for '" << args[1]
                 << "' failed with error: " << exit_code;
      return false;
  }
}

static std::optional<base::Value::Dict> GetVmInfo(const VmId& vm_id) {
  std::string output;
  if (!ExecutePvmHelper(vm_id.owner_id(),
                        {"list", "--info", "--json", vm_id.name()}, &output)) {
    return std::nullopt;
  }

  auto result = base::JSONReader::Read(output);
  if (!result) {
    LOG(ERROR) << "GetVmInfo(" << vm_id << "): Failed to parse VM info";
    return std::nullopt;
  }

  if (!result->is_list()) {
    LOG(ERROR) << "GetVmInfo(" << vm_id
               << "): Expected to find a list at top level";
    return std::nullopt;
  }

  if (result->GetList().size() != 1) {
    LOG(ERROR) << "GetVmInfo(" << vm_id << "): Unexpected list size of "
               << result->GetList().size() << ", expect 1";
    return std::nullopt;
  }

  base::Value& vm_info = result->GetList()[0];
  if (!vm_info.is_dict()) {
    LOG(ERROR) << "GetVmInfo(" << vm_id
               << "): Failed to fetch VM info dictionary";
    return std::nullopt;
  }

  return std::move(vm_info.GetDict());
}

bool DisconnectDevice(const VmId& vm_id, const std::string& device_name) {
  return ExecutePvmHelper(
      vm_id.owner_id(),
      {"set", vm_id.name(), "--device-disconnect", device_name});
}

}  // namespace

bool CreateVm(const VmId& vm_id, std::vector<std::string> params) {
  std::vector<std::string> args = {
      "create",
      vm_id.name(),
  };
  std::move(params.begin(), params.end(), std::back_inserter(args));
  return ExecutePvmHelper(vm_id.owner_id(), std::move(args));
}

bool AttachIso(const VmId& vm_id,
               const std::string& cdrom_name,
               const std::string& iso_name) {
  std::vector<std::string> args = {
      "set",     vm_id.name(), "--device-set", cdrom_name,
      "--image", iso_name,     "--connect",
  };
  return ExecutePvmHelper(vm_id.owner_id(), std::move(args));
}

bool CreateCdromDevice(const VmId& vm_id, const std::string& iso_name) {
  std::vector<std::string> args = {
      "set",     vm_id.name(), "--device-add", "cdrom",
      "--image", iso_name,     "--connect",
  };
  return ExecutePvmHelper(vm_id.owner_id(), std::move(args));
}

bool DeleteVm(const VmId& vm_id) {
  return ExecutePvmHelper(vm_id.owner_id(), {"delete", vm_id.name()});
}

void CleanUpAfterInstall(const VmId& vm_id, const base::FilePath& iso_path) {
  auto vm_info = GetVmInfo(vm_id);
  if (!vm_info) {
    LOG(ERROR) << "Failed to obtain VM info for " << vm_id;
    return;
  }

  const base::Value::Dict* hardware = vm_info->FindDict("Hardware");
  if (!hardware) {
    LOG(ERROR) << "Failed to obtain hardware info for " << vm_id;
    return;
  }

  for (const auto& [key, value] : *hardware) {
    if (!base::StartsWith(key, "cdrom"))
      continue;

    if (!value.is_dict()) {
      LOG(WARNING) << "Hardware node " << key << " in " << vm_id
                   << "is not a dictionary";
      continue;
    }
    const base::Value::Dict& cdrom = value.GetDict();

    const std::string* image_name = cdrom.FindString("image");
    if (!image_name)
      continue;  // The device is not backed by an image.

    LOG(INFO) << "CDROM image: " << *image_name;

    if (*image_name != plugin::kInstallIsoPath &&
        *image_name != plugin::kToolsIsoPath)
      continue;

    const std::string* state = cdrom.FindString("state");
    if (!state || *state != "disconnected") {
      if (!DisconnectDevice(vm_id, key)) {
        LOG(ERROR) << "Failed to disconnect " << key << " from " << vm_id;
        continue;
      }
    }

    if (*image_name == plugin::kInstallIsoPath) {
      base::FilePath iso_name =
          base::FilePath(plugin::kInstallIsoPath).BaseName();
      base::FilePath image_path = iso_path.Append(iso_name);
      if (base::PathExists(image_path) && !DeleteFile(image_path)) {
        LOG(WARNING) << "Failed to delete " << image_path.value();
      }
    }
  }
}

bool SetMemorySize(scoped_refptr<dbus::Bus> bus,
                   dbus::ObjectProxy* dispatcher_proxy,
                   const VmId& vm_id,
                   std::vector<std::string> params,
                   std::string* failure_message) {
  unsigned memsize;
  if (params.size() != 1 ||
      (params[0] != "auto" &&
       (!base::StringToUint(params[0], &memsize) || memsize == 0))) {
    *failure_message = "Invalid setting for the memory size";
    return false;
  }

  bool is_shut_down;
  if (!dispatcher::IsVmShutDown(bus, dispatcher_proxy, vm_id, &is_shut_down)) {
    *failure_message = "Unable to query VM state";
    return false;
  }

  if (!is_shut_down) {
    *failure_message = "The VM is not shut down";
    return false;
  }

  std::vector<std::string> args = {
      "set",
      vm_id.name(),
      "--memsize",
      params[0],
  };

  if (!ExecutePvmHelper(vm_id.owner_id(), std::move(args))) {
    *failure_message = "Failed to adjust VM memory size";
    return false;
  }

  return true;
}

bool ToggleSharedProfile(scoped_refptr<dbus::Bus> bus,
                         dbus::ObjectProxy* dispatcher_proxy,
                         const VmId& vm_id,
                         std::vector<std::string> params,
                         std::string* failure_message) {
  if (params.size() != 1 || (params[0] != "on" && params[0] != "off")) {
    *failure_message = "Invalid setting for the shared profile option";
    return false;
  }

  bool is_shut_down;
  if (!dispatcher::IsVmShutDown(bus, dispatcher_proxy, vm_id, &is_shut_down)) {
    *failure_message = "Unable to query VM state";
    return false;
  }

  if (!is_shut_down) {
    *failure_message = "The VM is not shut down";
    return false;
  }

  std::vector<std::string> args = {
      "set",
      vm_id.name(),
      "--shared-profile",
      params[0],
  };

  if (!ExecutePvmHelper(vm_id.owner_id(), std::move(args))) {
    *failure_message = "Failed to toggle shared profile option";
    return false;
  }

  return true;
}

}  // namespace helper
}  // namespace pvm
}  // namespace concierge
}  // namespace vm_tools
