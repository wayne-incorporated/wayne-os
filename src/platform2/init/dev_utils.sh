#!/bin/sh
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Utility functions for chromeos_startup to run in developer mode.

STATEFUL_PARTITION="/mnt/stateful_partition"

PRESERVE_DIR="${STATEFUL_PARTITION}/unencrypted/preserve"

# These paths will be preserved through clobbering.
PATHS_TO_PRESERVE=""
PATHS_TO_PRESERVE="${PATHS_TO_PRESERVE} /var/lib/servod"
PATHS_TO_PRESERVE="${PATHS_TO_PRESERVE} /usr/local/servod"
PATHS_TO_PRESERVE="${PATHS_TO_PRESERVE} /var/lib/device_health_profile"
PATHS_TO_PRESERVE="${PATHS_TO_PRESERVE} /usr/local/etc/wifi_creds"

# Returns if we are running on a debug build.
dev_is_debug_build() {
  crossystem 'debug_build?1'
}

# Keep this list in sync with the var_overlay elements in the DIRLIST
# found in chromeos-install from chromeos-base/chromeos-installer.
MOUNTDIRS="
  db/pkg
  lib/portage
  cache/dlc-images
"

# Unmount stateful partition for dev packages.
dev_unmount_packages() {
  # Unmount bind mounts for /var elements needed by gmerge.
  local base="/var"
  if [ -d "${base}" ]; then
    echo "${MOUNTDIRS}" | while read -r dir ; do
      if [ -n "${dir}" ]; then
        if [ ! -d "${base}/${dir}" ]; then
          continue
        fi
        umount -n "${base}/${dir}"
      fi
    done
  fi

  # unmount /usr/local to match dev_mount_package.
  umount -n /usr/local

  # If the dev image is mounted using a logical volume, unmount it.
  if mountpoint -q /mnt/stateful_partition/dev_image; then
    umount /mnt/stateful_partition/dev_image
  fi
}

# Copy contents in src path to dst path if it exists.
copy_path() {
  local src_path="$1"
  local dst_path="$2"
  if [ -d "${src_path}" ]; then
    mkdir -p "${dst_path}"
    cp -a "${src_path}/"* "${dst_path}"
  fi
}

# Pushes the array of paths to preserve to protected path.
dev_push_paths_to_preserve() {
  local path
  for path in ${PATHS_TO_PRESERVE}; do
    copy_path "${path}" "${PRESERVE_DIR}/${path}"
  done
}
