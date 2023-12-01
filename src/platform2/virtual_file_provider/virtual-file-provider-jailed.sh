#!/bin/sh
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Run virtual_file_provider with minijail0 for ARC container.
# The mount path is set to /mnt in the minijail namespace.

set -e

MOUNT_FLAGS="MS_NOSUID|MS_NODEV|MS_NOEXEC"

# Start virtual-file-provider with /mnt as FUSE mount point in the
# minijail namespace.
# --profile=minimalistic-mountns Use minimalistic-mountns profile.
# --no-fs-restrictions Disable Landlock in order to perform mount in the
#                      minimalistic-mountns profile.
# -e    Enter a new network namespace.
# -p -I Enter a new PID namespace and run the process as init (pid=1).
# -l    Enter a new IPC namespace.
# -c    Forbid all caps except CAP_SYS_ADMIN (for mount() syscall) and
#       CAP_SETPCAP (to drop capabilities when it's not needed).
# -u/-g Run as virtual-file-provider user/group.
# -k    Mount tmpfs on /mnt and /run.
# -b    /run/dbus is for D-Bus system bus socket.
#       /dev/fuse is for mounting FUSE file systems.
# -f    Assign freeze cgroup as
#       /sys/fs/cgroup/freezer/virtual-file-provider/cgroup.procs
exec minijail0 \
     --profile=minimalistic-mountns --no-fs-restrictions \
     -e \
     -p -I \
     -l \
     -c 0x200100 \
     -u virtual-file-provider -g virtual-file-provider -G \
     -k "tmpfs,/mnt,tmpfs,${MOUNT_FLAGS}" \
     -k "tmpfs,/run,tmpfs,${MOUNT_FLAGS}" \
     -b /run/dbus \
     -b /dev/fuse \
     -f /sys/fs/cgroup/freezer/virtual-file-provider/cgroup.procs \
     -- /usr/bin/virtual-file-provider --path=/mnt
