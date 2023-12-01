#!/bin/sh
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Run virtual_file_provider with minijail0 for ARCVM.
# The mount path is set to /run/arcvm/media/virtual_files in the
# concierge namespace so that files created can be shared with
# ARCVM. The concierge namespace is created in the pre-start script of
# vm_concierge.conf.

set -e

# Create MOUNT_PATH in the concierge namespace.
MOUNT_PATH="/run/arcvm/media/virtual_files"
nsenter --mount=/run/namespaces/mnt_concierge --no-fork \
  -- mkdir -p "${MOUNT_PATH}"

UID=655360 # android-root
GID=656437 # external_storage

# Start virtual-file-provider with MOUNT_PATH as FUSE mount point
# in the concierge namespace.
# -V /run/namespaces/mnt_concierge Enter the concierge mount namespace.
# -e    Enter a new network namespace.
# -l    Enter a new IPC namespace.
# -c    Forbid all caps except CAP_SYS_ADMIN (for mount() syscall) and
#       CAP_SETPCAP (to drop capabilities when it's not needed).
# -u/-g Run as virtual-file-provider user/group.
exec minijail0 \
  -V /run/namespaces/mnt_concierge \
  -e \
  -l \
  -c 0x200100 \
  -u virtual-file-provider -g virtual-file-provider -G \
  -- /usr/bin/virtual-file-provider --path="${MOUNT_PATH}" --uid="${UID}" \
    --gid="${GID}"
