#!/bin/sh
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Devices with integrated modems do not have on-chip storage, they are fed
# their persistent state by the AP. As part of the modem factory flow, a
# golden modem file system image (known as the FSG) is created, stored in
# the eMMC boot partition, and made read-only. A hash of that image is
# permanently blown into fuses. This script runs at boot, checks the FSG
# image in the stateful partition against the device fuses, and reloads
# the image from the eMMC boot partition upon mismatch.

JOB="verify_fsg.sh"
RMTFS_DIR=/var/lib/rmtfs
RMTFS_BOOT_DIR="${RMTFS_DIR}/boot"
FSG_PATH="${RMTFS_BOOT_DIR}/modem_fsg"
FSG_SOURCE="$(echo /dev/mmcblk*boot0)"

# Logging messages go directly to /dev/kmsg because we run before
# syslog is available.
logit() {
  echo "<6>${JOB}:" "$@" > /dev/kmsg
}

logwarn() {
  echo "<4>${JOB}:" "$@" > /dev/kmsg
}

logerr() {
  echo "<3>${JOB}:" "$@" > /dev/kmsg
}

# Read the FSG fuse hash, and store the result into
# fsg_fuse_hash.
read_fuses() {
  fuse_path="$(realpath /sys/bus/nvmem/devices/qfprom*/nvmem)"
  fsg_fuse_hash=
  if [ ! -r "${fuse_path}" ]; then
    logerr "Fuse driver does not appear to be loaded."
    return 1
  fi

  fsg_fuse_hash="$(dd if="${fuse_path}" bs=1 skip=$((0x750)) count=32 \
                     status=none | od -tx1 -vAn | tr -d ' \n')"
}

# Compare the FSG hash to what's in the fuses.
check_fsg_hash() {
  if [ ! -f "${FSG_PATH}" ]; then
    return 1
  fi

  read_fuses
  # If the fuses are unprogrammed, then return failure differently.
  local z16="0000000000000000"
  local unprogrammed="${z16}${z16}${z16}${z16}"
  if [ -z "${fsg_fuse_hash}" ] || \
     [ "${fsg_fuse_hash}" = "${unprogrammed}" ]; then
    return 2
  fi

  # Hash the FSG, and compare against what was burned into the fuses
  # in the factory.
  local fsg_hash

  fsg_hash="$(sha256sum < "${FSG_PATH}" | awk '{print $1}')"
  if [ "${fsg_hash}" != "${fsg_fuse_hash}" ]; then
    return 1
  fi

  return 0
}

# See if this is an old style eMMC partition, and load the size if so.
# Note: This function works by altering the fsg_size variable used by
# reload_fsg().
# TODO(evgreen): Delete this after the last P2A build.
# There is only expected to be one more P2A build.
load_old_fsg_size() {
  # In the old style format, there's just a size at 0 and the FSG at 512.
  fsg_size="$(dd if="${FSG_SOURCE}" bs=8 skip=0 count=1 status=none | \
              tr -d '\n\0' | grep -a -E '^[0-9]{4,}$')"

  : "${fsg_size:=0}"
}

# Read the FSG out of the eMMC boot partition.
reload_fsg() {
  local fsg_header
  local fsg_size=0
  local fsg_tmp_path="${FSG_PATH}.tmp"

  # Get the 3 byte header, which is "FSG".
  fsg_header="$(dd if="${FSG_SOURCE}" bs=3 skip=0 count=1 status=none)"
  if [ "${fsg_header}" = "FSG" ]; then
    fsg_size="$(dd if="${FSG_SOURCE}" bs=1 skip=4 count=8 status=none)"

  # If the header area is just blank, save an extra read and just bail now.
  elif [ -z "${fsg_header}" ]; then
    logit "Blank eMMC boot partition."
    return 1
  else
    # Ordinarily this would be the place to error out. For this next
    # build, also check for an "old-style" FSG.
    load_old_fsg_size
  fi

  # Wifi-only SKUs will land here the first time through.
  if [ "${fsg_size}" -eq 0 ]; then
    logit "No LTE FSG found."
    return 1
  fi

  logit "Reloading FSG"
  if [ "${fsg_size}" -gt 4193792 ]; then
    logwarn "Warning: FSG size invalid. LTE will not work."
  fi

  mkdir -p "${RMTFS_BOOT_DIR}"
  chmod 0700 "${RMTFS_BOOT_DIR}" "${RMTFS_DIR}"
  rm -f "${FSG_PATH}" "${fsg_tmp_path}"

  # Copy to a temporary file and rename to avoid ending up with a
  # partially loaded file in case of power loss.
  # Ensure the dd succeeded.
  if ! dd if="${FSG_SOURCE}" of="${fsg_tmp_path}" bs=1M \
        iflag=count_bytes,skip_bytes count="${fsg_size}" \
        skip=512 status=none; then

    logerr "Error: Failed to read FSG."
    return 1
  fi

  # Sync to ensure the temporary file is fully written to disk. Then
  # move the final file into place as an atomic op.
  # This sync could be slow, but FSG reloading is also rare.
  sync
  mv "${fsg_tmp_path}" "${FSG_PATH}"
  sync
}

verify_fsg() {
  local retval

  # Check the FSG hash against the fuses. Reload from the eMMC boot
  # partition if it fails.
  check_fsg_hash
  retval=$?
  if [ "${retval}" -eq 0 ]; then
    return
  elif [ "${retval}" -eq 2 ]; then
    # For WiFi SKUs, the first factory run, or for certain pre-production
    # devices), the FSG hash is not set. Allow it to continue with the FSG
    # tarball pre-populated in the boot partition.
    logit "Fuses are unprogrammed."

    # If the FSG already exists no need to copy it again; bail out.
    if [ -f "${FSG_PATH}" ]; then
      return
    fi
  fi

  if ! reload_fsg; then
    # Perhaps this is a wifi-only SKU.
    return
  fi

  check_fsg_hash
  retval=$?
  if [ "${retval}" -eq 0 ]; then
    # Delete all EFS images in case they got corrupted and that
    # causes the modem to crash or hang rather than turning to the FSG.
    # Only do this if the hash now agrees, otherwise developers with
    # unprogrammed fuses will be constantly fighting this deletion.
    rm -f "${RMTFS_BOOT_DIR}"/modem_fs[c12]
  elif [ "${retval}" -ne 2 ]; then
    # Allow a hash mismatch in dev/test images.
    if crossystem "cros_debug?1" ; then
      logwarn "FSG hash check failed, forgiven in developer mode."

    # For other errors, blank out the FSG in case the eMMC boot partition
    # was compromised.
    else
      logerr "FSG hash check failed. LTE will not work"
      rm -f "${FSG_PATH}"
    fi
  fi
}

main() {
  if [ "$#" -ne 0 ]; then
    logerr "$0: Expected no arguments."
    exit 1
  fi

  verify_fsg
}

main "$@"
