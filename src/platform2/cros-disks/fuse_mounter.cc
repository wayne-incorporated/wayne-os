// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/fuse_mounter.h"

#include <base/check.h>
#include <base/check_op.h>

// Has to come before linux/fs.h due to conflicting definitions of MS_*
// constants.
#include <sys/mount.h>

#include <fcntl.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/containers/contains.h>
#include <base/files/file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/weak_ptr.h>
#include <base/stl_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "cros-disks/mount_point.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/sandboxed_process.h"

namespace cros_disks {
namespace {

// Gets the physical block size of the given block device.
// Returns 0 in case of error.
int GetPhysicalBlockSize(const std::string& source) {
  const base::ScopedFD fd(open(source.c_str(), O_RDONLY | O_CLOEXEC));
  if (!fd.is_valid()) {
    PLOG(WARNING) << "Cannot open device " << quote(source);
    return 0;
  }

  int block_size;
  if (ioctl(fd.get(), BLKPBSZGET, &block_size) < 0) {
    PLOG(WARNING) << "Cannot get block size of device " << quote(source);
    return 0;
  }

  DCHECK_GE(block_size, 0);
  LOG(INFO) << "Device " << quote(source) << " has a block size of "
            << block_size << " bytes";
  return block_size;
}

}  // namespace

FUSESandboxedProcessFactory::FUSESandboxedProcessFactory(
    const Platform* platform,
    SandboxedExecutable executable,
    OwnerUser run_as,
    bool has_network_access,
    bool kill_pid_namespace,
    std::vector<gid_t> supplementary_groups,
    std::optional<base::FilePath> mount_namespace)
    : platform_(platform),
      executable_(std::move(executable.executable)),
      seccomp_policy_(std::move(executable.seccomp_policy)),
      run_as_(std::move(run_as)),
      has_network_access_(has_network_access),
      kill_pid_namespace_(kill_pid_namespace),
      supplementary_groups_(std::move(supplementary_groups)),
      mount_namespace_(std::move(mount_namespace)) {
  CHECK(executable_.IsAbsolute());
  if (seccomp_policy_) {
    CHECK(seccomp_policy_.value().IsAbsolute());
  }
  if (mount_namespace_) {
    CHECK(mount_namespace_.value().IsAbsolute());
  }
}

FUSESandboxedProcessFactory::~FUSESandboxedProcessFactory() = default;

std::unique_ptr<SandboxedProcess>
FUSESandboxedProcessFactory::CreateSandboxedProcess() const {
  std::unique_ptr<SandboxedProcess> sandbox =
      std::make_unique<SandboxedProcess>();
  if (!ConfigureSandbox(sandbox.get()))
    sandbox.reset();
  return sandbox;
}

bool FUSESandboxedProcessFactory::ConfigureSandbox(
    SandboxedProcess* sandbox) const {
  sandbox->SetCapabilities(0);
  sandbox->SetNoNewPrivileges();

  // The FUSE mount program is put under a new mount namespace, so mounts
  // inside that namespace don't normally propagate.
  sandbox->NewMountNamespace();
  sandbox->NewIpcNamespace();
  sandbox->NewPidNamespace();

  sandbox->NewCgroupNamespace();

  sandbox->SetKillPidNamespace(kill_pid_namespace_);

  // Add the sandboxed process to its cgroup that should be setup. Return an
  // error if it's not there.
  const base::FilePath cgroup = base::FilePath("/sys/fs/cgroup/freezer")
                                    .Append(executable_.BaseName())
                                    .Append("cgroup.procs");

  if (!platform_->PathExists(cgroup.value())) {
    PLOG(ERROR) << "Freezer cgroup " << quote(cgroup) << " is missing";
    return false;
  }

  if (!sandbox->AddToCgroup(cgroup.value())) {
    LOG(ERROR) << "Cannot add sandboxed process to cgroup " << quote(cgroup);
    return false;
  }

  // Prepare mounts for pivot_root.
  if (!sandbox->SetUpMinimalMounts()) {
    LOG(ERROR) << "Cannot set up minijail mounts";
    return false;
  }

  // /run is the place where mutable system configs are being kept.
  // We don't expose them by default, but to be able to bind them when
  // needed /run needs to be writeable.
  if (!sandbox->Mount("tmpfs", "/run", "tmpfs", "mode=0755,size=1M")) {
    LOG(ERROR) << "Cannot mount /run";
    return false;
  }

  if (!has_network_access_) {
    sandbox->NewNetworkNamespace();
  } else {
    // Network DNS configs are in /run/shill.
    // TODO(259354228): Remove once resolv.conf migration to dns-proxy is done.
    if (const std::string p = "/run/shill";
        !sandbox->BindMount(p, p, false, false)) {
      PLOG(ERROR) << "Cannot bind-mount " << quote(p);
      return false;
    }

    // Network DNS configs are in /run/dns-proxy.
    if (const std::string p = "/run/dns-proxy";
        !sandbox->BindMount(p, p, false, false)) {
      PLOG(ERROR) << "Cannot bind-mount " << quote(p);
      return false;
    }

    // Hardcoded hosts are mounted into /etc/hosts.d when Crostini is enabled.
    if (const std::string p = "/etc/hosts.d";
        platform_->PathExists(p) && !sandbox->BindMount(p, p, false, false)) {
      PLOG(ERROR) << "Cannot bind-mount " << quote(p);
      return false;
    }
  }

  if (!sandbox->EnterPivotRoot()) {
    LOG(ERROR) << "Cannot pivot root";
    return false;
  }

  if (seccomp_policy_) {
    if (!platform_->PathExists(seccomp_policy_.value().value())) {
      LOG(ERROR) << "Seccomp policy " << quote(seccomp_policy_.value())
                 << " is missing";
      return false;
    }
    sandbox->LoadSeccompFilterPolicy(seccomp_policy_.value().value());
  }

  sandbox->SetUserId(run_as_.uid);
  sandbox->SetGroupId(run_as_.gid);

  if (!supplementary_groups_.empty())
    sandbox->SetSupplementaryGroupIds(supplementary_groups_);

  // Enter mount namespace in the sandbox if necessary.
  if (mount_namespace_)
    sandbox->EnterExistingMountNamespace(mount_namespace_.value().value());

  if (!platform_->PathExists(executable_.value())) {
    LOG(ERROR) << "Cannot find mounter program " << quote(executable_);
    return false;
  }

  sandbox->AddArgument(executable_.value());

  return true;
}

FUSEMounter::FUSEMounter(const Platform* platform,
                         brillo::ProcessReaper* process_reaper,
                         std::string filesystem_type,
                         Config config)
    : platform_(platform),
      process_reaper_(process_reaper),
      filesystem_type_(std::move(filesystem_type)),
      config_(std::move(config)) {}

FUSEMounter::~FUSEMounter() = default;

std::unique_ptr<MountPoint> FUSEMounter::Mount(
    const std::string& source,
    const base::FilePath& target_path,
    std::vector<std::string> params,
    MountError* const error) const {
  // Read-only is the only parameter that has any effect at this layer.
  const bool read_only = config_.read_only || IsReadOnlyMount(params);

  const base::FilePath fuse_device_path("/dev/fuse");
  base::File fuse_file = base::File(
      fuse_device_path,
      base::File::FLAG_OPEN | base::File::FLAG_READ | base::File::FLAG_WRITE);
  if (!fuse_file.IsValid()) {
    LOG(ERROR) << "Cannot open FUSE device " << quote(fuse_device_path) << ": "
               << base::File::ErrorToString(fuse_file.error_details());
    *error = MountError::kInternalError;
    return nullptr;
  }

  // Mount options for FUSE:
  // fd - File descriptor for /dev/fuse.
  // user_id/group_id - user/group for file access control. Essentially
  //     bypassed due to allow_other, but still required to be set.
  // allow_other - Allows users other than user_id/group_id to access files
  //     on the file system. By default, FUSE prevents any process other than
  //     ones running under user_id/group_id to access files, regardless of
  //     the file's permissions.
  // default_permissions - Enforce permission checking.
  // rootmode - Mode bits for the root inode.
  std::string fuse_mount_options = base::StringPrintf(
      "fd=%d,user_id=%u,group_id=%u,allow_other,default_permissions,"
      "rootmode=%o",
      fuse_file.GetPlatformFile(), kChronosUID, kChronosAccessGID, S_IFDIR);

  std::string fuse_type = "fuse";
  base::stat_wrapper_t statbuf = {0};
  if (platform_->Lstat(source, &statbuf) && S_ISBLK(statbuf.st_mode)) {
    // TODO(crbug.com/931500): It's possible that specifying a block size equal
    // to the file system cluster size (which might be larger than the physical
    // block size) might be more efficient. Data would be needed to see what
    // kind of performance benefit, if any, could be gained. At the very least,
    // specify the block size of the underlying device. Without this, UFS cards
    // with 4k sector size will fail to mount.
    if (const int blksize = GetPhysicalBlockSize(source))
      fuse_mount_options.append(base::StringPrintf(",blksize=%d", blksize));

    fuse_type = "fuseblk";
  }

  if (!filesystem_type_.empty()) {
    fuse_type += ".";
    fuse_type += filesystem_type_;
  }

  // Prepare mount flags.
  uint64_t mount_flags = MS_NODEV | MS_NOSUID | MS_NOEXEC | MS_DIRSYNC;

  if (read_only)
    mount_flags |= MS_RDONLY;

  if (config_.nosymfollow)
    mount_flags |= MS_NOSYMFOLLOW;

  std::unique_ptr<MountPoint> mount_point =
      MountPoint::Mount({.mount_path = target_path,
                         .source = source,
                         .filesystem_type = fuse_type,
                         .flags = mount_flags,
                         .data = fuse_mount_options},
                        platform_, error);

  if (!mount_point) {
    DCHECK_NE(*error, MountError::kSuccess);
    return nullptr;
  }

  // Start FUSE daemon.
  std::unique_ptr<SandboxedProcess> process = StartDaemon(
      std::move(fuse_file), source, target_path, std::move(params), error);

  if (!process) {
    DCHECK_NE(*error, MountError::kSuccess);
    LOG(ERROR) << "Cannot start FUSE daemon for " << redact(source) << ": "
               << *error;
    return nullptr;
  }

  mount_point->SetProcess(std::move(process), config_.metrics,
                          config_.metrics_name,
                          config_.password_needed_exit_codes);

  *error = MountError::kSuccess;
  return mount_point;
}

std::unique_ptr<SandboxedProcess> FUSEMounter::StartDaemon(
    base::File fuse_file,
    const std::string& source,
    const base::FilePath& target_path,
    std::vector<std::string> params,
    MountError* const error) const {
  DCHECK(error);

  std::unique_ptr<SandboxedProcess> process =
      PrepareSandbox(source, target_path, std::move(params), error);

  if (!process) {
    DCHECK_NE(*error, MountError::kSuccess);
    return nullptr;
  }

  const int fd = fuse_file.GetPlatformFile();
  process->AddArgument(base::StringPrintf("/dev/fd/%d", fd));
  process->PreserveFile(fd);

  process->SetOutputCallback(base::DoNothing());

  if (!process->Start()) {
    *error = MountError::kMountProgramNotFound;
    return nullptr;
  }

  return process;
}

FUSEMounterHelper::FUSEMounterHelper(
    const Platform* platform,
    brillo::ProcessReaper* process_reaper,
    std::string filesystem_type,
    bool nosymfollow,
    const SandboxedProcessFactory* sandbox_factory)
    : FUSEMounter(platform,
                  process_reaper,
                  std::move(filesystem_type),
                  {.nosymfollow = nosymfollow}),
      sandbox_factory_(sandbox_factory) {}

FUSEMounterHelper::~FUSEMounterHelper() = default;

std::unique_ptr<SandboxedProcess> FUSEMounterHelper::PrepareSandbox(
    const std::string& source,
    const base::FilePath& target_path,
    std::vector<std::string> params,
    MountError* const error) const {
  DCHECK(error);

  std::unique_ptr<SandboxedProcess> sandbox =
      sandbox_factory_->CreateSandboxedProcess();
  if (!sandbox) {
    *error = MountError::kInternalError;
    return nullptr;
  }

  *error =
      ConfigureSandbox(source, target_path, std::move(params), sandbox.get());
  if (*error != MountError::kSuccess)
    return nullptr;

  return sandbox;
}

}  // namespace cros_disks
