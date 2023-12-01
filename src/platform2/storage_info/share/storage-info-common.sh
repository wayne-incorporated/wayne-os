#!/bin/sh

# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script provides various data about the internal disk to show on the
# chrome://system page. It will run once on startup to dump output to the file
# /var/log/storage_info.txt which will be read later by debugd when the user
# opens the chrome://system page.

# Dash does not support arrays, so this script uses name composition instead.
# This would cause false positives from cros lint for unused names, so the
# warning is disabled here:
# shellcheck disable=SC2034

. /usr/share/misc/chromeos-common.sh

# This match SanDisk SSD U100/i100 with any size with version *.xx.* when x < 54
# Seen Error with U100 10.52.01 / i100 CS.51.00 / U100 10.01.04.
MODEL_IGNORELIST_0="SanDisk_SSD_[iU]100.*"
VERSION_IGNORELIST_0="(CS|10)\.([01234].|5[0123])\..*"
MODEL_IGNORELIST_1="SanDisk_SDSA5GK-.*"
VERSION_IGNORELIST_1="CS.54.06"
MODEL_IGNORELIST_2="LITEON_LST-.*"
VERSION_IGNORELIST_2=".*"
MODEL_IGNORELIST_3="LITEON_CS1-SP.*"
VERSION_IGNORELIST_3=".*"
MODEL_IGNORELIST_4="LITEON_L8H-.*"
VERSION_IGNORELIST_4=".*"
MODEL_IGNORELIST_5="LITEON_LMH-.*"
VERSION_IGNORELIST_5=".*"
IGNORELIST_MAX=5

MMC_NAME_0="cid"
MMC_NAME_1="csd"
MMC_NAME_2="date"
MMC_NAME_3="enhanced_area_offset"
MMC_NAME_4="enhanced_area_size"
MMC_NAME_5="erase_size"
MMC_NAME_6="fwrev"
MMC_NAME_7="hwrev"
MMC_NAME_8="manfid"
MMC_NAME_9="name"
MMC_NAME_10="oemid"
MMC_NAME_11="preferred_erase_size"
MMC_NAME_12="prv"
MMC_NAME_13="raw_rpmb_size_mult"
MMC_NAME_14="rel_sectors"
MMC_NAME_15="serial"
MMC_NAME_MAX=15

# exapnd_var - evaluates a variable represented by a string
#
# inputs:
#   variable name
#
# outputs:
#   output of variable's evaluation
expand_var() {
  eval "echo \"\${$1}\""
}

# echo_run - print command, and then execute it
#
# inputs:
#   command to run
#
# outputs:
#   result of the command execution
echo_run() {
  local ret=0
  echo "$ $*"
  "$@" || ret=$?
  echo ""
  return "${ret}"
}

# get_ssd_model - Return the model name of an ATA device.
#
# inputs:
#   output of hdparm -i command.
#
# outputs:
#   the model name of the device, sanitized of space and punctuation.
get_ssd_model() {
  echo "$1" | sed -e "s/^.*Model=//g" -e "s/,.*//g" -e "s/ /_/g"
}

# get_ssd_version - Return the firmware version of an ATA device.
#
# inputs:
#   output of hdparm -i command.
#
# outputs:
#   the version of the device firmware, sanitized of space and punctuation.
get_ssd_version() {
  echo "$1" | sed -e "s/^.*FwRev=//g" -e "s/,.*//g" -e "s/ /_/g"
}

# is_ignorelist - helper function for is_ssd_ignorelist.
#
# inputs:
#   the information from the device.
#   the ignorelist element to match against.
is_ignorelist() {
  echo "$1" | grep -Eq "$2"
}

# is_ssd_ignorelist - Return true is the device is ignorelisted.
#
# inputs:
#   model : model of the ATA device.
#   version : ATA device firmware version.
#
# outputs:
#   True if the device belongs into the script ignorelist.
#   When an ATA device is in the ignorelist, only a subset of the ATA SMART
#   output is displayed.
is_ssd_ignorelist() {
  local model="$1"
  local version="$2"
  local model_ignorelist
  local version_ignorelist
  local i

  for i in $(seq 0 "${IGNORELIST_MAX}"); do
    model_ignorelist=$(expand_var "MODEL_IGNORELIST_${i}")
    if is_ignorelist "${model}" "${model_ignorelist}"; then
      version_ignorelist=$(expand_var "VERSION_IGNORELIST_${i}")
      if is_ignorelist "${version}" "${version_ignorelist}"; then
        return 0
      fi
    fi
  done
  return 1
}

# print_ssd_info - Print SATA device information
#
# inputs:
#   device name for instance sdb.
print_ssd_info() {
  # BUG: On some machines, smartctl -x causes SSD error (crbug.com/328587).
  # We need to check model and firmware version of the SSD to avoid this bug.
  local hdparm_result
  local model
  local version

  # SSD model and firmware version is on the same line in hdparm result.
  hdparm_result="$(hdparm -i "/dev/$1" | grep "Model=")"
  model="$(get_ssd_model "${hdparm_result}")"
  version="$(get_ssd_version "${hdparm_result}")"

  echo_run hdparm -I "/dev/$1"

  if is_ssd_ignorelist "${model}" "${version}"; then
    echo_run smartctl -a -f brief "/dev/$1"
  else
    echo_run smartctl -x "/dev/$1"
  fi
}

# print_mmc_info - Print eMMC device information
#
# inputs:
#   device name for instance mmcblk0.
print_mmc_info() {
  local mmc_name
  local mmc_path
  local mmc_result
  local i

  for i in $(seq 0 "${MMC_NAME_MAX}"); do
    mmc_name=$(expand_var "MMC_NAME_${i}")
    mmc_path="/sys/block/$1/device/${mmc_name}"
    mmc_result="$(cat "${mmc_path}" 2>/dev/null)"
    printf "%-20s | %s\n" "${mmc_name}" "${mmc_result}"
  done

  mmc extcsd read "/dev/$1"
}

# print_nvme - Print NVMe device information
#
# inputs:
#   device name for instance nvme0n1.
print_nvme_info() {
  echo_run smartctl -x "/dev/$1"
}

# print_ufs_info - Print UFS device information
# inputs:
#   device name for instance sdb.
print_ufs_info() {
  # TODO(dlunev, b:219839139): deduce it instead of hardcoding.
  local bsg_dev="/dev/bsg/ufs-bsg0"
  local dev_node="/sys/block/${dev}/device"

  echo "Device: /dev/$1"
  echo "Vendor:" "$(cat "${dev_node}"/vendor)"
  echo "Model:" "$(cat "${dev_node}"/model)"
  echo "Firmware:" "$(cat "${dev_node}"/rev)"
  echo ""

  echo_run ufs-utils desc -a -p "${bsg_dev}"
  echo_run ufs-utils attr -a -p "${bsg_dev}"
  echo_run ufs-utils fl -a -p "${bsg_dev}"
  echo_run ufs-utils uic -t 0 -a -p "${bsg_dev}"
  echo_run ufs-utils uic -t 1 -a -p "${bsg_dev}"
  echo_run ufs-utils uic -t 2 -a -p "${bsg_dev}"
  # BUG: the commands above set error code if any field it expects is missing.
  # Given that the tool is generic for UFS3.1 and UFS2.1, it may attempt to
  # query UFS3 a attributes on UFS2 device. We want to ignore those partial
  # failures.
  echo ""
}

# get_storage_info - Print device information.
#
# Print device information for all fixed devices in the system.
get_storage_info() {
  local dev

  for dev in $(list_fixed_ata_disks); do
    print_ssd_info "${dev}"
  done

  for dev in $(list_fixed_mmc_disks); do
    print_mmc_info "${dev}"
  done

  for dev in $(list_fixed_nvme_disks); do
    print_nvme_info "${dev}"
  done

  for dev in $(list_fixed_ufs_disks); do
    print_ufs_info "${dev}"
  done
}
