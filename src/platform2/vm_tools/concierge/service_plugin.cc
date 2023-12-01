// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/socket.h>
#include <sys/types.h>

#include <string>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/uuid.h>

#include "vm_tools/concierge/plugin_vm.h"
#include "vm_tools/concierge/plugin_vm_helper.h"
#include "vm_tools/concierge/service.h"
#include "vm_tools/concierge/shared_data.h"
#include "vm_tools/concierge/vm_base_impl.h"
#include "vm_tools/concierge/vmplugin_dispatcher_interface.h"

namespace vm_tools {
namespace concierge {

namespace {

bool GetPluginStatefulDirectory(const std::string& vm_id,
                                const std::string& cryptohome_id,
                                bool create,
                                base::FilePath* path_out) {
  return GetPluginDirectory(base::FilePath(kCryptohomeRoot)
                                .Append(kPluginVmDir)
                                .Append(cryptohome_id),
                            "pvm", vm_id, create, path_out);
}

bool GetPluginRuntimeDirectory(const std::string& vm_id,
                               base::ScopedTempDir* runtime_dir_out) {
  base::FilePath path;
  if (GetPluginDirectory(base::FilePath("/run/pvm"), "", vm_id,
                         true /*create */, &path)) {
    // Take ownership of directory
    CHECK(runtime_dir_out->Set(path));
    return true;
  }

  return false;
}

bool GetPluginRootDirectory(const std::string& vm_id,
                            base::ScopedTempDir* root_dir_out) {
  base::FilePath path;
  if (!base::CreateTemporaryDirInDir(base::FilePath(kRuntimeDir), "vm.",
                                     &path)) {
    PLOG(ERROR) << "Unable to create root directory for VM";
    return false;
  }

  // Take ownership of directory
  CHECK(root_dir_out->Set(path));
  return true;
}

bool CreatePluginRootHierarchy(const base::FilePath& root_path) {
  base::FilePath etc_dir(root_path.Append("etc"));
  base::File::Error dir_error;
  if (!CreateDirectoryAndGetError(etc_dir, &dir_error)) {
    LOG(ERROR) << "Unable to create /etc in root directory for VM "
               << base::File::ErrorToString(dir_error);
    return false;
  }

  // Note that this will be dangling (or rather point to concierge's timezone
  // instance) until crosvm bind mounts /var/lib/timezone and
  // /usr/share/zoneinfo into plugin jail.
  if (!base::CreateSymbolicLink(base::FilePath("/var/lib/timezone/localtime"),
                                etc_dir.Append("localtime"))) {
    PLOG(ERROR) << "Unable to create /etc/localtime symlink";
    return false;
  }

  return true;
}

bool GetPlugin9PSocketPath(const std::string& vm_id, base::FilePath* path_out) {
  base::FilePath runtime_dir;
  if (!GetPluginDirectory(base::FilePath("/run/pvm"), "", vm_id,
                          true /* create */, &runtime_dir)) {
    LOG(ERROR) << "Unable to get runtime directory for 9P socket";
    return false;
  }

  *path_out = runtime_dir.Append("9p.sock");
  return true;
}

}  // namespace

void Service::StartPluginVm(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        vm_tools::concierge::StartVmResponse>> response_sender,
    const vm_tools::concierge::StartPluginVmRequest& request) {
  LOG(INFO) << "Received StartPluginVm request";
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  StartVmResponse response;
  // We change to a success status later if necessary.
  response.set_status(VM_STATUS_FAILURE);

  if (!CheckStartVmPreconditions(request, &response)) {
    response_sender->Return(response);
    return;
  }

  StartPluginVmInternal(request, response);
  response_sender->Return(response);
}

StartVmResponse Service::StartPluginVmInternal(StartPluginVmRequest request,
                                               StartVmResponse& response) {
  LOG(INFO) << "Received StartPluginVm request";
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  VmInfo* vm_info = response.mutable_vm_info();
  vm_info->set_vm_type(VmInfo::PLUGIN_VM);

  // Get the stateful directory.
  base::FilePath stateful_dir;
  if (!GetPluginStatefulDirectory(request.name(), request.owner_id(),
                                  true /* create */, &stateful_dir)) {
    LOG(ERROR) << "Unable to create stateful directory for VM";

    response.set_failure_reason("Unable to create stateful directory");
    return response;
  }

  // Get the directory for ISO images.
  base::FilePath iso_dir;
  if (!GetPluginIsoDirectory(request.name(), request.owner_id(),
                             true /* create */, &iso_dir)) {
    LOG(ERROR) << "Unable to create directory holding ISOs for VM";

    response.set_failure_reason("Unable to create ISO directory");
    return response;
  }

  // Create the runtime directory.
  base::ScopedTempDir runtime_dir;
  if (!GetPluginRuntimeDirectory(request.name(), &runtime_dir)) {
    LOG(ERROR) << "Unable to create runtime directory for VM";

    response.set_failure_reason("Unable to create runtime directory");
    return response;
  }

  // Create the root directory.
  base::ScopedTempDir root_dir;
  if (!GetPluginRootDirectory(request.name(), &root_dir)) {
    LOG(ERROR) << "Unable to create runtime directory for VM";

    response.set_failure_reason("Unable to create runtime directory");
    return response;
  }

  if (!CreatePluginRootHierarchy(root_dir.GetPath())) {
    response.set_failure_reason("Unable to create plugin root hierarchy");
    return response;
  }

  if (!PluginVm::WriteResolvConf(root_dir.GetPath().Append("etc"), nameservers_,
                                 search_domains_)) {
    LOG(ERROR) << "Unable to seed resolv.conf for the Plugin VM";

    response.set_failure_reason("Unable to seed resolv.conf");
    return response;
  }

  // Generate the token used by cicerone to identify the VM and write it to
  // a VM specific directory that gets mounted into the VM.
  std::string vm_token = base::Uuid::GenerateRandomV4().AsLowercaseString();
  if (base::WriteFile(runtime_dir.GetPath().Append("cicerone.token"),
                      vm_token.c_str(),
                      vm_token.length()) != vm_token.length()) {
    PLOG(ERROR) << "Failure writing out cicerone token to file";

    response.set_failure_reason("Unable to set cicerone token");
    return response;
  }

  base::FilePath p9_socket_path;
  if (!GetPlugin9PSocketPath(request.name(), &p9_socket_path)) {
    response.set_failure_reason("Internal error: unable to get 9P directory");
    return response;
  }

  base::ScopedFD p9_socket =
      PluginVm::CreateUnixSocket(p9_socket_path, SOCK_STREAM);
  if (!p9_socket.is_valid()) {
    LOG(ERROR) << "Failed creating 9P socket for file sharing";

    response.set_failure_reason("Internal error: unable to create 9P socket");
    return response;
  }

  std::unique_ptr<patchpanel::Client> network_client =
      patchpanel::Client::New(bus_);
  if (!network_client) {
    LOG(ERROR) << "Unable to open networking service client";

    response.set_failure_reason("Unable to open network service client");
    return response;
  }

  std::unique_ptr<SeneschalServerProxy> seneschal_server_proxy =
      SeneschalServerProxy::CreateFdProxy(bus_, seneschal_service_proxy_,
                                          p9_socket);
  if (!seneschal_server_proxy) {
    LOG(ERROR) << "Unable to start shared directory server";

    response.set_failure_reason("Unable to start shared directory server");
    return response;
  }

  // Build the plugin params.
  std::vector<std::string> params(
      std::make_move_iterator(request.mutable_params()->begin()),
      std::make_move_iterator(request.mutable_params()->end()));

  // Now start the VM.
  VmId vm_id(request.owner_id(), request.name());
  SendVmStartingUpSignal(vm_id, *vm_info);

  VmBuilder vm_builder;
  vm_builder.SetCpus(request.cpus());
  vm_builder.AppendCustomParam("--vcpu-cgroup-path",
                               base::FilePath(kPluginVmVcpuCpuCgroup).value());
  for (auto& param : params) {
    // Because additional parameters may start with a '--', we should use
    // --params=<Param> instead of --params <Param> to make explicit <Param>
    // is a parameter for the plugin rather than just another parameter to
    // the crosvm process.
    vm_builder.AppendCustomParam(std::string("--params=") + param, "");
  }

  auto vm = PluginVm::Create(PluginVm::Config{
      .id = vm_id,
      .stateful_dir = std::move(stateful_dir),
      .iso_dir = std::move(iso_dir),
      .root_dir = root_dir.Take(),
      .runtime_dir = runtime_dir.Take(),
      .network_client = std::move(network_client),
      .subnet_index = static_cast<int>(request.subnet_index()),
      .enable_vnet_hdr = request.net_options().enable_vnet_hdr(),
      .bus = bus_,
      .seneschal_server_proxy = std::move(seneschal_server_proxy),
      .vm_permission_service_proxy = vm_permission_service_proxy_,
      .vmplugin_service_proxy = vmplugin_service_proxy_,
      .vm_builder = std::move(vm_builder)});
  if (!vm) {
    LOG(ERROR) << "Unable to start VM";
    response.set_failure_reason("Unable to start VM");
    return response;
  }

  VmBaseImpl::Info info = vm->GetInfo();

  vm_info->set_ipv4_address(info.ipv4_address);
  vm_info->set_pid(info.pid);
  vm_info->set_cid(info.cid);
  vm_info->set_seneschal_server_handle(info.seneschal_server_handle);
  vm_info->set_permission_token(info.permission_token);
  switch (info.status) {
    case VmBaseImpl::Status::STARTING: {
      response.set_status(VM_STATUS_STARTING);
      break;
    }
    case VmBaseImpl::Status::RUNNING: {
      response.set_status(VM_STATUS_RUNNING);
      break;
    }
    default: {
      response.set_status(VM_STATUS_UNKNOWN);
      break;
    }
  }
  response.set_success(true);

  NotifyCiceroneOfVmStarted(vm_id, 0 /* cid */, info.pid, std::move(vm_token));
  HandleVmStarted(vm_id, *vm_info, vm->GetVmSocketPath(), response.status());

  vms_[vm_id] = std::move(vm);
  return response;
}

bool Service::RenamePluginVm(const std::string& owner_id,
                             const std::string& old_name,
                             const std::string& new_name,
                             std::string* failure_reason) {
  base::FilePath old_dir;
  if (!GetPluginStatefulDirectory(old_name, owner_id, false /* create */,
                                  &old_dir)) {
    *failure_reason = "unable to determine current VM directory";
    return false;
  }

  base::FilePath old_iso_dir;
  if (!GetPluginIsoDirectory(old_name, owner_id, false /* create */,
                             &old_iso_dir)) {
    *failure_reason = "unable to determine current VM ISO directory";
    return false;
  }

  base::FilePath new_dir;
  if (!GetPluginStatefulDirectory(new_name, owner_id, false /* create */,
                                  &new_dir)) {
    *failure_reason = "unable to determine new VM directory";
    return false;
  }

  base::FilePath new_iso_dir;
  if (!GetPluginIsoDirectory(new_name, owner_id, false /* create */,
                             &new_iso_dir)) {
    *failure_reason = "unable to determine new VM ISO directory";
    return false;
  }

  VmId old_id(owner_id, old_name);
  bool registered;
  if (!pvm::dispatcher::IsVmRegistered(bus_, vmplugin_service_proxy_, old_id,
                                       &registered)) {
    *failure_reason = "failed to check Plugin VM registration status";
    return false;
  }

  // This is unexpected: the VM is not registered. Better leave it alone.
  if (!registered) {
    *failure_reason = "the VM is not registered";
    return false;
  }

  bool is_shut_down;
  if (!pvm::dispatcher::IsVmShutDown(bus_, vmplugin_service_proxy_, old_id,
                                     &is_shut_down)) {
    *failure_reason = "failed to check Plugin VM state";
    return false;
  }

  if (!is_shut_down) {
    *failure_reason = "VM is not shut down";
    return false;
  }

  base::File::Error move_error;
  if (base::PathExists(old_iso_dir) &&
      !base::ReplaceFile(old_iso_dir, new_iso_dir, &move_error)) {
    *failure_reason = std::string("failed to rename VM ISO directory: ") +
                      base::File::ErrorToString(move_error);
    return false;
  }

  if (!pvm::dispatcher::UnregisterVm(bus_, vmplugin_service_proxy_, old_id)) {
    *failure_reason = "failed to temporarily unregister VM";
    return false;
  }

  if (!base::ReplaceFile(old_dir, new_dir, &move_error)) {
    *failure_reason = std::string("failed to rename VM directory: ") +
                      base::File::ErrorToString(move_error);
    return false;
  }

  if (!pvm::dispatcher::RegisterVm(bus_, vmplugin_service_proxy_,
                                   VmId(owner_id, new_name), new_dir)) {
    *failure_reason = "Failed to re-register renamed VM";
    return false;
  }

  return true;
}

}  // namespace concierge
}  // namespace vm_tools
