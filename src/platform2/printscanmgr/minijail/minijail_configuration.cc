// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/minijail/minijail_configuration.h"

#include <base/check_op.h>
#include <libminijail.h>
#include <scoped_minijail.h>

namespace printscanmgr {

namespace {

// User and group to run as.
constexpr char kPrintscanmgrUserName[] = "printscanmgr";
constexpr char kPrintscanmgrGroupName[] = "printscanmgr";

// Path to the SECCOMP filter to apply.
constexpr char kSeccompFilterPath[] =
    "/usr/share/policy/printscanmgr-seccomp.policy";

}  // namespace

void EnterDaemonMinijail() {
  ScopedMinijail jail(minijail_new());
  minijail_no_new_privs(jail.get());   // The no_new_privs bit.
  minijail_namespace_uts(jail.get());  // New UTS namespace.
  minijail_namespace_ipc(jail.get());  // New IPC namespace.
  minijail_namespace_vfs(jail.get());  // New VFS namespace.
  minijail_mount_tmp(jail.get());
  CHECK_EQ(
      0, minijail_enter_pivot_root(jail.get(),
                                   "/mnt/empty"));  // Set /mnt/empty as rootfs.

  CHECK_EQ(0, minijail_bind(jail.get(), "/", "/", 0));

  CHECK_EQ(1, minijail_add_fs_restriction_ro(jail.get(), "/"));
  CHECK_EQ(1, minijail_add_fs_restriction_rx(jail.get(), "/bin"));
  CHECK_EQ(1, minijail_add_fs_restriction_rx(jail.get(), "/etc"));
  CHECK_EQ(1, minijail_add_fs_restriction_rx(jail.get(), "/lib"));
  CHECK_EQ(1, minijail_add_fs_restriction_rx(jail.get(), "/lib64"));
  CHECK_EQ(1, minijail_add_fs_restriction_rx(jail.get(), "/usr/sbin"));
  CHECK_EQ(1, minijail_add_fs_restriction_rx(jail.get(), "/usr/bin"));
  CHECK_EQ(1, minijail_add_fs_restriction_rx(jail.get(), "/usr/lib64"));
  CHECK_EQ(1, minijail_add_fs_restriction_rx(jail.get(), "/usr/libexec"));
  CHECK_EQ(1, minijail_add_fs_restriction_rw(jail.get(), "/tmp"));

  // Create a new tmpfs filesystem for /run and mount necessary files.
  CHECK_EQ(
      0, minijail_mount_with_data(jail.get(), "tmpfs", "/run", "tmpfs", 0, ""));
  CHECK_EQ(0, minijail_bind(
                  jail.get(), "/run/dbus", "/run/dbus",
                  0));  // Shared socket file for talking to the D-Bus daemon.
  CHECK_EQ(1, minijail_add_fs_restriction_rw(jail.get(), "/run/dbus"));
  CHECK_EQ(0, minijail_bind(jail.get(), "/run/cups", "/run/cups",
                            0));  // Shared socket file for talking to cupsd.
  CHECK_EQ(1, minijail_add_fs_restriction_rw(jail.get(), "/run/cups"));

  // Run as the printscanmgr user and group. Inherit supplementary groups so
  // printscanmgr can run `lpadmin` and `lpstat`.
  CHECK_EQ(0, minijail_change_user(jail.get(), kPrintscanmgrUserName));
  CHECK_EQ(0, minijail_change_group(jail.get(), kPrintscanmgrGroupName));
  minijail_inherit_usergroups(jail.get());

  // Apply SECCOMP filtering.
  minijail_use_seccomp_filter(jail.get());
  minijail_parse_seccomp_filters(jail.get(), kSeccompFilterPath);

  minijail_enter(jail.get());
}

void EnterExecutorMinijail() {
  ScopedMinijail j(minijail_new());

  // Create a minimalistic mount namespace with just the bare minimum required.
  minijail_namespace_vfs(j.get());
  minijail_mount_tmp(j.get());
  CHECK_EQ(0, minijail_enter_pivot_root(j.get(), "/mnt/empty"));

  CHECK_EQ(0, minijail_bind(j.get(), "/", "/", 0));

  minijail_enter(j.get());
}

}  // namespace printscanmgr
