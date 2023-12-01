// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/minijail/minijail_configuration.h"

#include <sys/capability.h>
#include <sys/mount.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <libminijail.h>
#include <scoped_minijail.h>

namespace rmad {

namespace {

constexpr char kRmadUser[] = "rmad";
constexpr char kRmadGroup[] = "rmad";
constexpr char kRmadSeccompFilterPath[] =
    "/usr/share/policy/rmad-seccomp.policy";
constexpr char kRmadExecutorSeccompFilterPath[] =
    "/usr/share/policy/rmad-executor-seccomp.policy";

// Checks to see if |file_path| exists on the device. If it does, it will be
// bind-mounted inside |jail| at the same path it exists outside the minijail,
// and it will not be writeable from inside |jail|.
void BindMountIfPathExists(struct minijail* jail,
                           const base::FilePath& file_path) {
  if (!base::PathExists(file_path))
    return;

  const char* path_string = file_path.value().c_str();
  minijail_bind(jail, path_string, path_string, 0);
}

}  // namespace

void EnterMinijail(bool set_admin_caps) {
  ScopedMinijail j(minijail_new());
  minijail_no_new_privs(j.get());
  minijail_remount_proc_readonly(j.get());
  minijail_namespace_ipc(j.get());
  minijail_namespace_net(j.get());
  minijail_namespace_uts(j.get());
  minijail_namespace_vfs(j.get());

  minijail_change_user(j.get(), kRmadUser);
  minijail_change_group(j.get(), kRmadGroup);
  minijail_inherit_usergroups(j.get());

  minijail_enter_pivot_root(j.get(), "/mnt/empty");

  minijail_mount_tmp(j.get());

  minijail_bind(j.get(), "/", "/", 0);
  minijail_add_fs_restriction_ro(j.get(), "/");

  minijail_bind(j.get(), "/dev", "/dev", 0);
  minijail_bind(j.get(), "/proc", "/proc", 0);

  minijail_mount_with_data(j.get(), "tmpfs", "/run", "tmpfs", 0, nullptr);

  // Required to read cros_config.
  minijail_bind(j.get(), "/run/chromeos-config/v1", "/run/chromeos-config/v1",
                0);
  minijail_add_fs_restriction_ro(j.get(), "/run/chromeos-config/v1");

  // Required to parse cros_config_fs.
  minijail_bind(j.get(), "/run/chromeos-config/private",
                "/run/chromeos-config/private", 0);
  minijail_add_fs_restriction_ro(j.get(), "/run/chromeos-config/private");

  // Required for using D-Bus.
  minijail_bind(j.get(), "/run/dbus", "/run/dbus", 0);
  minijail_add_fs_restriction_ro(j.get(), "/run/dbus");

  // Required by |mojo_service_manager| utility.
  minijail_bind(j.get(), "/run/mojo", "/run/mojo", 0);
  minijail_add_fs_restriction_ro(j.get(), "/run/mojo");

  // Required by |vpd| utility.
  minijail_bind(j.get(), "/run/lock", "/run/lock", 1);
  minijail_add_fs_restriction_rw(j.get(), "/run/lock");

  minijail_mount_with_data(j.get(), "tmpfs", "/var", "tmpfs", 0, nullptr);

  // Required to write structured metrics.
  minijail_bind(j.get(), "/var/lib/metrics/structured",
                "/var/lib/metrics/structured", 1);
  minijail_add_fs_restriction_rw(j.get(), "/var/lib/metrics/structured");

  // Required to access rmad working directory.
  minijail_bind(j.get(), "/var/lib/rmad", "/var/lib/rmad", 1);
  minijail_add_fs_restriction_rw(j.get(), "/var/lib/rmad");

  // Required to read system logs.
  minijail_bind(j.get(), "/var/log", "/var/log", 0);
  minijail_add_fs_restriction_ro(j.get(), "/var/log");

  minijail_mount_with_data(j.get(), "tmpfs", "/sys", "tmpfs", 0, nullptr);

  // Required to read HWWP GPIO and sensor attributes.
  minijail_bind(j.get(), "/sys/devices", "/sys/devices", 0);
  minijail_add_fs_restriction_ro(j.get(), "/sys/devices");

  // Required to read HWWP GPIO and sensor attributes.
  minijail_bind(j.get(), "/sys/class", "/sys/class", 0);
  minijail_add_fs_restriction_ro(j.get(), "/sys/class");

  // Required to read VPD and sensor attributes.
  minijail_bind(j.get(), "/sys/bus", "/sys/bus", 0);
  minijail_add_fs_restriction_ro(j.get(), "/sys/bus");

  // Required to read system properties (crossystem) on arm.
  BindMountIfPathExists(j.get(),
                        base::FilePath("/sys/firmware/devicetree/base"));
  minijail_add_fs_restriction_ro(j.get(), "/sys/firmware/devicetree/base");

  minijail_mount_with_data(j.get(), "tmpfs", "/mnt/stateful_partition", "tmpfs",
                           0, nullptr);

  // Required to write rmad state file.
  minijail_bind(j.get(), "/mnt/stateful_partition/unencrypted/rma-data",
                "/mnt/stateful_partition/unencrypted/rma-data", 1);
  minijail_add_fs_restriction_rw(
      j.get(), "/mnt/stateful_partition/unencrypted/rma-data");

  // Required to read powerwash_count.
  minijail_bind(j.get(), "/mnt/stateful_partition/unencrypted/preserve",
                "/mnt/stateful_partition/unencrypted/preserve", 0);
  minijail_add_fs_restriction_ro(
      j.get(), "/mnt/stateful_partition/unencrypted/preserve");

  if (set_admin_caps) {
    minijail_use_caps(j.get(), CAP_TO_MASK(CAP_SYS_RAWIO) |
                                   CAP_TO_MASK(CAP_DAC_OVERRIDE) |
                                   CAP_TO_MASK(CAP_SYS_ADMIN));
    minijail_set_ambient_caps(j.get());
    // Required to read (not even write) VPD, but only accessible with the
    // capabilities above.
    // TODO(chenghan): Can we move VPD to executor?
    minijail_bind(j.get(), "/dev/mem", "/dev/mem", 0);
    minijail_add_fs_restriction_ro(j.get(), "/dev/mem");
  } else {
    // TODO(jeffulin): Withdraw this cap after we move the function of getting
    // HWWP to executor.
    minijail_use_caps(j.get(), CAP_TO_MASK(CAP_DAC_OVERRIDE));
  }

  minijail_set_using_minimalistic_mountns(j.get());
  minijail_add_minimalistic_mountns_fs_rules(j.get());

  minijail_use_seccomp_filter(j.get());
  minijail_parse_seccomp_filters(j.get(), kRmadSeccompFilterPath);

  minijail_enter(j.get());
}

void NewMountNamespace() {
  // Create a minimalistic mount namespace with just the bare minimum required.
  // Reference: debugd/src/main.cc
  ScopedMinijail j(minijail_new());

  minijail_namespace_vfs(j.get());
  minijail_mount_tmp(j.get());
  minijail_enter_pivot_root(j.get(), "/mnt/empty");

  minijail_bind(j.get(), "/", "/", 0);

  // Mount stateful partition to write powerwash request file.
  minijail_bind(j.get(), "/mnt/stateful_partition", "/mnt/stateful_partition",
                1);

  minijail_mount_with_data(j.get(), "none", "/proc", "proc",
                           MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr);
  minijail_mount_with_data(j.get(), "tmpfs", "/run", "tmpfs",
                           MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr);
  // Mount /sys and /dev to be able to inspect devices.
  minijail_mount_with_data(j.get(), "/dev", "/dev", "bind", MS_BIND | MS_REC,
                           nullptr);
  minijail_bind(j.get(), "/dev/cros_ec", "/dev/cros_ec", 0);
  minijail_mount_with_data(j.get(), "/sys", "/sys", "bind", MS_BIND | MS_REC,
                           nullptr);
  // Mount /var to access rmad working directory.
  minijail_mount_with_data(j.get(), "tmpfs", "/var", "tmpfs", 0, nullptr);
  minijail_bind(j.get(), "/var/lib/rmad", "/var/lib/rmad", 1);

  // Required by |crossystem| utility.
  minijail_bind(j.get(), "/run/lock", "/run/lock", 1);

  minijail_use_seccomp_filter(j.get());
  minijail_parse_seccomp_filters(j.get(), kRmadExecutorSeccompFilterPath);

  minijail_enter(j.get());
}

}  // namespace rmad
