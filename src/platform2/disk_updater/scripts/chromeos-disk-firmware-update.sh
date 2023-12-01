#!/bin/sh

# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Chrome OS Disk Firmware Update Script
# This script checks whether if the root device needs to be upgraded.
#

. /usr/share/misc/shflags
. /usr/share/misc/chromeos-common.sh

# Temporary directory to put device information
DEFINE_string 'tmp_dir' '' "Use existing temporary directory."
DEFINE_string 'fw_package_dir' '' "Location of the firmware package."
DEFINE_string 'hdparm' 'hdparm' "hdparm binary to use."
DEFINE_string 'hdparm_kingston' '/opt/google/disk/bin/hdparm_kingston' \
              "hdparm for kingston recovery."
DEFINE_string 'smartctl' 'smartctl' "smartctl binary to use."
DEFINE_string 'pwr_suspend' 'powerd_dbus_suspend' "To power cycle SSD"
DEFINE_string 'mmc' 'mmc' "mmc binary to use."
DEFINE_string 'nvme' 'nvme' "nvme binary to use."
DEFINE_string 'status' '' "Status file to write to."
DEFINE_boolean 'test' ${FLAGS_FALSE} "For unit testing."

# list global variables
#   disk_model
#   disk_fw_rev
#   disk_fw_file
#   disk_exp_fw_rev
#   disk_fw_opt
#   nvme_out : A file where the output of "nvme id-ctrl" is stored.

log_msg() {
  logger -t "chromeos-disk-firmware-update[${PPID}]" "$@"
  echo "$@"
}

die() {
  log_msg "error: $*"
  exit 1
}

# Parse command line
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# program_installed - check if the specified program is installed.
program_installed() {
  if ! command -v "$1" > /dev/null; then
    log_msg "$1 is not installed"
    return 1
  fi
}
# disk_fw_select - Select the proper disk firmware to use.
#
# This code reuse old installer disk firmware upgrade code.
#
# inputs:
#     disk_rules        -- the file containing the list of rules.
#     disk_model        -- the model from hdparm -I
#     disk_fw_rev       -- the firmware version of the device.
#
# outputs:
#     disk_fw_file      -- name of the DISK firmware image file for this machine
#     disk_exp_fw_rev   -- the revision code of the firmware
#     disk_fw_opt       -- the options for this update
#
disk_fw_select() {
  local disk_rules="$1"
  local rule_model
  local rule_fw_rev
  local rule_exp_fw_rev
  local rule_fw_opt
  local rule_fw_file
  disk_fw_file=""
  disk_exp_fw_rev=""
  disk_fw_opt=""

  # Check for obvious misconfiguration problems:
  if [ -z "${disk_rules}" ]; then
    log_msg "Warning: disk_rules not specified"
    return 1
  fi
  if [ ! -r "${disk_rules}" ]; then
    log_msg "Warning: cannot read config file ${disk_rules}"
    return 1
  fi

  # Read through the config file, looking for matches:
  while read -r rule_model rule_fw_rev rule_exp_fw_rev rule_fw_opt rule_fw_file; do
    if [ -z "${rule_fw_file}" ]; then
      log_msg "${disk_rules}: incorrect number of items in file"
      continue
    fi

    # Check for match:
    if [ "${disk_model}" != "${rule_model}" ]; then
      continue
    fi
    if [ "${disk_fw_rev}" != "${rule_fw_rev}" ]; then
      continue
    fi
    disk_exp_fw_rev="${rule_exp_fw_rev}"
    disk_fw_opt="${rule_fw_opt}"
    disk_fw_file="${rule_fw_file}"
  done < "${disk_rules}"

  # If we got here, then no DISK firmware matched.
  if [ -z "${disk_fw_file}" ]; then
    return 1
  else
    return 0
  fi
}

# disk_hdparm_info - Shim for calling hdparm
#
# Useful for testing overide.
#
# inputs:
#     device            -- the device name [sda,...]
#
# echo the output of hdparm.
#
disk_hdparm_info() {
  local device="$1"

  # Test if we have the tool needed for an upgrade.
  if ! program_installed "${FLAGS_hdparm}"; then
    return 1
  fi

  # use -I option to be sure the drive is accessed:
  # will fail if the drive is not up
  # sure that the firmware version is up to date if the
  # disk upgrade without reset.
  "${FLAGS_hdparm}" -I "/dev/${device}"
}

# disk_nvme_id_info - Shim for calling nvme id-ctrl command
#
# Useful for testing overide.
#
# inputs:
#     device            -- the device name [nvme0,...]
#
# echo the output of nvme id-ctrl.
#
disk_nvme_id_info() {
  local device="$1"

  "${FLAGS_nvme}" id-ctrl "/dev/${device}"
}

#disk_mmc_info - Retrieve disk information for MMC device
#
# inputs:
#     device            -- the device name [mmcblk0]
#
# outputs:
#     disk_model        -- model of the device
#     disk_fw_rev       -- actual firmware revision on the device
#
# returns non 0 on error
#
disk_mmc_info() {
  # Some vendor use hexa decimal character for indentification.
  disk_model="$(cat "/sys/block/$1/device/cid" | cut -c 7-18)"
  disk_fw_rev="$(cat "/sys/block/$1/device/fwrev")"

  # Test if we have the tool needed for an upgrade.
  if ! program_installed "${FLAGS_mmc}"; then
    return 1
  fi

  if [ -z "${disk_model}" ] || [ -z "${disk_fw_rev}" ]; then
    return 1
  fi
  return 0
}

# disk_ata_info - Retrieve disk information for ata device
#
# inputs:
#     device            -- the device name [sda]
#
# outputs:
#     disk_model        -- model of the device
#     disk_fw_rev       -- actual firmware revision on the device
#
# returns non 0 on error
#
disk_ata_info() {
  local device="$1"
  local rc=0
  local hdparm_out="${FLAGS_tmp_dir}/${device}"

  disk_model=""
  disk_fw_rev=""
  disk_hdparm_info "${device}" > "${hdparm_out}"
  rc=$?
  if [ "${rc}" -ne 0 ]; then
    return "${rc}"
  fi
  if [ ! -s "${hdparm_out}" ]; then
    log_msg "hdparm did not produced any output"
    return 1
  fi
  disk_model=$(sed -nEe \
      '/^\t+Model/s|\t+Model Number: +(.*)|\1|p' "${hdparm_out}" \
    | sed -re 's/ +$//' -e 's/[ -]/_/g')
  disk_fw_rev=$(sed -nEe \
      '/^\t+Firmware/s|\t+Firmware Revision: +(.*)|\1|p' "${hdparm_out}" \
    | sed -re 's/ +$//' -e 's/[ -]/_/g')
  if [ -z "${disk_model}" ] || [ -z "${disk_fw_rev}" ]; then
    return 1
  fi
  return 0
}

# disk_nvme_info - Retrieve disk information for NMVe device
#
# inputs:
#     device            -- the device name [nvme0]
#
# outputs:
#     disk_model        -- model of the device
#     disk_fw_rev       -- actual firmware revision on the device
#
# returns non 0 on error
#
disk_nvme_info() {
  local device="$1"
  local rc=0
  nvme_out="${FLAGS_tmp_dir}/${device}"

  # Test if we have the tool needed for an upgrade.
  if ! program_installed "${FLAGS_nvme}"; then
    return 1
  fi

  # Use -I option to be sure the drive is accessed.
  disk_model=""
  disk_fw_rev=""
  disk_nvme_id_info "${device}" > "${nvme_out}"
  rc=$?
  if [ "${rc}" -ne 0 ]; then
    return "${rc}"
  fi
  if [ ! -s "${nvme_out}" ]; then
    log_msg "nvme did not produced any output"
    return 1
  fi
  disk_model=$(sed -nEe '/^mn +:/s|[^:]*: +(.*)|\1|p' "${nvme_out}" \
    | sed -re 's/ +$//' -e 's/[ -]/_/g')
  disk_fw_rev=$(sed -nEe '/^fr +:/s|[^:]*: +(.*)|\1|p' "${nvme_out}" \
    | sed -re 's/ +$//' -e 's/[ -]/_/g')
  if [ -z "${disk_model}" ] || [ -z "${disk_fw_rev}" ]; then
    return 1
  fi
  return 0
}

# disk_info - Retrieve model and firmware version from disk
#
# Call the appropriate function for the device type.
#
# inputs:
#     device            -- the device name
#
# outputs:
#     disk_model        -- model of the device
#     disk_fw_rev       -- actual firmware revision on the device
#
# returns non 0 on error
#
disk_info() {
  local device="$1"
  local device_type
  device_type="$(get_device_type "/dev/${device}")"
  case ${device_type} in
    "ATA")
      disk_ata_info "$@"
      ;;
    "MMC")
      disk_mmc_info "$@"
      ;;
    "NVME")
      disk_nvme_info "$@"
      ;;
    *)
      log_msg "Unknown device(${device}) type: ${device_type}"
      return 1
  esac
}

# disk_ata_power_cnt - Get the number of power cycle
#
# inputs:
#     device            -- the device name [sda,...]
#
disk_ata_power_cnt() {
  local device="$1"

  "${FLAGS_smartctl}" -A "/dev/${device}" | awk '
    BEGIN { count = 0 }
    $2 == "Power_Cycle_Count" { count = $10 }
    END { print count }
    '
}

# samus_ata1_power_cycle - Power Cycle the Samus uSSD
#
# When reformatting the samus uSSD, we can not use powerd.
# Toggle manually GPIOs.
samus_ata1_power_cycle() {
  # SSD_RESET_L : 47 => 256 - 94 + 47 = 209
  # PP3300_SSD_EN : 21 => 256 - 94 + 21 = 183
  local SSD_RESET_L_ID=209
  local PP3300_SSD_EN=183
  local GPIO_PATH="/sys/class/gpio"

  local SSD_RESET_L_ID_PATH="${GPIO_PATH}/gpio${SSD_RESET_L_ID}"
  local PP3300_SSD_EN_PATH="${GPIO_PATH}/gpio${PP3300_SSD_EN}"

  local EXPORT_PATH="${GPIO_PATH}/export"

  local device="$1"

  if [ ! -d "${SSD_RESET_L_ID_PATH}" ]; then
    for i in ${SSD_RESET_L_ID} ${PP3300_SSD_EN}; do
      echo $i > "${EXPORT_PATH}"
    done
    echo out > "${SSD_RESET_L_ID_PATH}/direction"
    echo 1 > "${SSD_RESET_L_ID_PATH}/active_low"

    echo out > "${PP3300_SSD_EN_PATH}/direction"

    echo 1 > "${PP3300_SSD_EN_PATH}/value"
    echo 0 > "${SSD_RESET_L_ID_PATH}/value"
  fi

  # Down.
  echo 1 > "${SSD_RESET_L_ID_PATH}/value"
  sleep 1
  echo 0 > "${PP3300_SSD_EN_PATH}/value"

  sleep 4
  # Up.
  echo 1 > "${PP3300_SSD_EN_PATH}/value"
  sleep 1
  echo 0 > "${SSD_RESET_L_ID_PATH}/value"

  disk_hdparm_info "${device}" > /dev/null
}

# disk_ata_power_cycle - Power cycle ATA SSD
#
# Suspend/resume the machine to power cycle the SSD.
#
# inputs:
#     device            -- the device name [sda,...]
#
# returns non 0 on error
#
disk_ata_power_cycle() {
  local device="$1"
  local tries=4
  local old_pwr_cycle_count
  local new_pwr_cycle_count

  old_pwr_cycle_count="$(disk_ata_power_cnt "${device}")"
  new_pwr_cycle_count="${old_pwr_cycle_count}"
  # Gather power cycle count.
  while [ "${old_pwr_cycle_count}" -eq "${new_pwr_cycle_count}" ] && \
        [ "${tries}" -gt 0 ]; do
     : $(( tries -= 1 ))
     "${FLAGS_pwr_suspend}" --wakeup_timeout=4 --timeout=10
     new_pwr_cycle_count="$(disk_ata_power_cnt "${device}")"
  done
  if [ "${old_pwr_cycle_count}" -eq "${new_pwr_cycle_count}" ]; then
    log_msg "Unable to power cycle ${device}"
  fi
}


# disk_hdparm_upgrade - Upgrade the firmware on the disk
#
# Update the firmware on the disk.
# TODO(gwendal): We assume the device can be updated in one shot.
#                In a future version, we may place a
#                a deep charge and reboot the machine.
#
# inputs:
#     device            -- the device name [sda,...]
#     fw_file           -- the firmware image
#     fw_options        -- the options from the rule file.
#
# returns non 0 on error
#
disk_hdparm_upgrade() {
  local device="$1"
  local fw_file="$2"
  local fw_options="$3"
  local hdparm_opt="--fwdownload-mode7"
  local power_cyle="true"
  local use_regular_hdparm="true"

  if [ "${fw_options}" != "-" ]; then
    if echo "${fw_options}" | grep -q "mode3_max"; then
      hdparm_opt="--fwdownload-mode3-max"
    fi
    if echo "${fw_options}" | grep -q "power_cycle"; then
      power_cyle="disk_ata_power_cycle"
    fi
    if echo "${fw_options}" | grep -q "kingston_erase"; then
      use_regular_hdparm=false
      power_cyle="samus_ata1_power_cycle"
      "${FLAGS_hdparm_kingston}" --eraseall "/dev/${device}"
    fi
    if echo "${fw_options}" | grep -q "kingston_reformat"; then
      use_regular_hdparm=false
      power_cyle="samus_ata1_power_cycle"
      "${FLAGS_hdparm_kingston}" --mp_f1 "${fw_file}" \
        "KINGSTON_RBU_SUS151S3rr" "/dev/${device}"
    fi
  fi

  if "${use_regular_hdparm}"; then
    # hdparm_opt could be several options, shell must see separator.
    "${FLAGS_hdparm}" ${hdparm_opt} "${fw_file}" \
      --yes-i-know-what-i-am-doing --please-destroy-my-drive \
      "/dev/${device}"
  fi

  if [ $? -ne 0 ]; then
    return $?
  fi

  ${power_cyle} "${device}"
}

# disk_mmc_upgrade - Upgrade the firmware on the eMMC storage
#
# Update the firmware on the disk.
#
# inputs:
#     device            -- the device name [sda,...]
#     fw_file           -- the firmware image
#     fw_options        -- the options from the rule file. (unused)
#
# returns non 0 on error
#
disk_mmc_upgrade() {
  local device="$1"
  local fw_file="$2"
  local fw_options="$3"
  local options=""

  if [ "${fw_options}" = "new" ]; then
     "${FLAGS_mmc}" ffu "${fw_file}" "/dev/${device}"
     return $?
  fi

  if [ "${fw_options}" != "-" ]; then
     # Options for mmc in the config files are separated with commas.
     # Translate the option for the command line.
     options="$(echo "${fw_options}" | sed 's/,/ -k /g')"
     options="-k ${options}"
  fi

  "${FLAGS_mmc}" old_ffu ${options} "${fw_file##*/}" "/dev/${device}"
}

# disk_nmve_reset - Reset  NMVE SSD PCIe device.
#
# Reset the PCIe device hosting the NMVe device.
#
# inputs:
#     device            -- the device name [nvme0,...]
#
# returns non 0 on error
#
disk_nmve_reset() {
  local device="$1"

  # Name space 1 is required to exits:
  echo 1 > "/sys/block/${device}n1/device/device/reset"
}

# disk_nvme_current_slot - Retrieve which slot the current firmware comes from.
#
# Information is located in the first byte of Log 3
# (Firmware Slot Information Log).
#
# Return the slot number, assume nvme device is up.
disk_nvme_current_slot() {
  local device="$1"

  local byte0="$("${FLAGS_nvme}" get-log "/dev/${device}" \
      --raw-binary --log-id 3 --log-len 512 | \
      od -An -t u1 -N 1)"
  echo $((byte0 & 0x3))
}

# disk_nvme_get_frmw - get FRMW from identity data.
#
# Use already collected id-ctrl data, and extrace the Firmware Updates field.
# The fields have the following format:
#
#  7    5  4 3   1 0
#  +------+-+-----+-+
#  |      | |     | |
#  +------+-+-----+-+
#          \   \   \
#           \   \   --- slot 1 is read only, can not be use for update.
#            \   ------ number of slot available (between 1 and 7)
#             --------- action 3 (upgrade without reset available)
disk_nvme_get_frmw() {
  local device="$1"
  grep "frmw" "${nvme_out}" | cut -d ':' -f 2
}

disk_nvme_get_min_writable_slot() {
  local frmw="$1"
  # Slot 1 can be read only, check frmw bit 0.
  echo $(((frmw & 0x1) + 1))
}

disk_nvme_get_max_writable_slot() {
  local frmw="$1"
  # Bit 1 - 3 of frmw contains the number of slots.
  echo $(((frmw & 0xe) >> 1))
}

# disk_nvme_action_supported - Return supported action
#
# Return the commit action the device is supporting:
# - 3 : the device can upgrade without reset,
# - 2 : the device needs reset to upgrade (mandatory).
disk_nvme_action_supported() {
  local frmw="$1"
  # Bit 4 of frmw indicates if upgrade without reset is supported.
  echo $((((frmw & 0x10) >> 4) + 2))
}

# disk_nvme_upgrade - Upgrade the firmware on the NVME storage
#
# Update the firmware on the disk.
#
# inputs:
#     device            -- the device name [nvme0,...]
#     fw_file           -- the firmware image
#     fw_options        -- the options from the rule file.
#
# By default the NVMe device can be upgraded without reset (commit action 3),
# see NVMe 1.3 Figure 76. If reset is needed, we use commit action 2.
#
# returns non 0 on error
#
disk_nvme_upgrade() {
  local device="$1"
  local fw_file="$2"
  local fw_options="$3"
  local frmw="$(disk_nvme_get_frmw "${device}")"
  local action="$(disk_nvme_action_supported "${frmw}")"
  local curr_slot="$(disk_nvme_current_slot "${device}")"
  local min_slot="$(disk_nvme_get_min_writable_slot "${frmw}")"
  local max_slot="$(disk_nvme_get_max_writable_slot "${frmw}")"
  local new_slot rc

  if echo "${fw_options}" | grep -q "bh799"; then
    # BH799 requires to use the current slot (3). Other slots are used for eMMC
    # firmware upgrade.
    new_slot="$((curr_slot))"
    # BH799 only support action 1, not 0+2.
    action=1
  elif [ "${curr_slot}" -eq "${max_slot}" ]; then
    new_slot="${min_slot}"
  else
    new_slot="$((curr_slot + 1))"
  fi
  if echo "${fw_options}" | grep -q "separate_slot"; then
    if [ "${new_slot}" -eq "${curr_slot}" ]; then
      log_msg "Unable to find proper slot: current ${curr_slot}, " \
              "min: ${min_slot}, max: ${max_slot}"
      return 1
    fi
  fi

  "${FLAGS_nvme}" fw-download "/dev/${device}" --fw="${fw_file}"
  rc=$?
  if [ "${rc}" -ne 0 ]; then
    log_msg "Unable to download ${fw_file} to ${device}"
    return "${rc}"
  fi

  # Use action 0 to download image into slot.
  if [ "${action}" -ne 1 ]; then
    "${FLAGS_nvme}" fw-activate "/dev/${device}" --slot="${new_slot}" --action=0
    rc=$?
    if [ "${rc}" -ne 0 ]; then
       log_msg "Unable to load ${fw_file} to ${device}"
       return "${rc}"
    fi
  fi
  "${FLAGS_nvme}" fw-activate "/dev/${device}" --slot="${new_slot}" \
    --action="${action}"
  rc=$?
  if [ "${rc}" -eq 11 ] && [ "${action}" -ne 0 ]; then
    disk_nmve_reset "${device}"
  elif [ "${rc}" -ne 0 ]; then
    log_msg "Unable to activate ${fw_file} to ${device}"
    return "${rc}"
  elif echo "${fw_options}" | grep -q "bh799"; then
    # BH799 report the firmware has been updated, but it needs a reset.
    "${FLAGS_nvme}" reset "/dev/${device}"
  fi
}

# disk_upgrade - Upgrade the firmware on the disk
#
# Update the firmware on the disk by calling the function appropriate for
# the transport.
#
# inputs:
#     device            -- the device name [sda,...]
#     fw_file           -- the firmware image
#     fw_options        -- the options from the rule file.
#
# returns non 0 on error
#
disk_upgrade() {
  local device="$1"
  local device_type
  device_type="$(get_device_type "/dev/${device}")"
  case ${device_type} in
    "ATA")
      disk_hdparm_upgrade "$@"
      ;;
    "MMC")
      disk_mmc_upgrade "$@"
      ;;
    "NVME")
      disk_nvme_upgrade "$@"
      ;;
    *)
      log_msg "Unknown device(${device}) type: ${device_type}"
      return 1
  esac
}

# disk_upgrade_devices - Look for firmware upgrades
#
# major function: look for a rule match and upgrade.
# updated in one shot. In a future version, we may place a
# a deep charge and reboot the machine.
#
# input:
#    list of devices to upgrade.
# retuns 0 on sucess
#    The error code of hdparm or other functions that fails
#    120 if no rules is provided
#    121 when the disk works but the firmware was not applied.
#
disk_upgrade_devices() {
  local disk_rules="$1"
  local device
  local fw_file
  local success
  local disk_old_fw_rev=""
  local rc=0
  local tries=0

  shift # skip disk rules parameters.
  for device in "$@"; do
    sucess=""
    while true; do
      disk_info "${device}"  # sets disk_model, disk_fw_rev
      rc=$?
      if [ "${rc}" -ne 0 ]; then
        log_msg "Can not get info on this device. skip."
        rc=0
        break
      fi
      disk_fw_select "${disk_rules}"  # sets disk_fw_file, disk_exp_fw_rev, disk_fw_opt
      rc=$?
      if [ "${rc}" -ne 0 ]; then
        # Nothing to do, go to next drive if any.
        : "${success:="No need to upgrade ${device}:${disk_model}"}"
        log_msg "${success}"
        rc=0
        break
      fi
      fw_file="${FLAGS_fw_package_dir}/${disk_fw_file}"
      if [ ! -f "${fw_file}" ]; then
        fw_file="${FLAGS_tmp_dir}/${disk_fw_file}"
        bzcat "${FLAGS_fw_package_dir}/${disk_fw_file}.bz2" > "${fw_file}" 2> /dev/null
        rc=$?
        if [ "${rc}" -ne 0 ]; then
          log_msg "${disk_fw_file} in ${FLAGS_fw_package_dir} could not be extracted: ${rc}"
          break
        fi
      fi
      disk_old_fw_rev="${disk_fw_rev}"
      disk_upgrade "${device}" "${fw_file}" "${disk_fw_opt}"
      rc=$?
      if [ "${rc}" -ne 0 ]; then
        # Will change in the future if we need to power cycle, reboot...
        log_msg "Unable to upgrade ${device} from ${disk_fw_rev} to ${disk_exp_fw_rev}"
        break
      else
        # Allow the kernel to recover
        tries=4
        rc=1
        # Verify that's the firmware upgrade stuck It may take some time.
        while [ "${tries}" -ne 0 ] && [ "${rc}" -ne 0 ]; do
          : $(( tries -= 1 ))
          # Allow the error handler to block the scsi queue if it is working.
          if [ "${FLAGS_test}" -eq "${FLAGS_FALSE}" ]; then
            sleep 1
          fi
          disk_info "${device}"
          rc=$?
        done
        if [ "${rc}" -ne 0 ]; then
          # We are in trouble. The disk was expected to come back but did not.
          # TODO(gwendal): Shall we have a preemptive message to ask to
          # powercycle?
          break
        fi
        if [ "${disk_exp_fw_rev}" = "${disk_fw_rev}" ]; then
          # We are good, go to the next drive if any.
          if [ -n "${success}" ]; then
            success="${success}
"
          fi
          success="${success}Upgraded ${device}:${disk_model} from"
          success="${success} ${disk_old_fw_rev} to ${disk_fw_rev}"
          # Continue, in case we need upgrade in several steps.
          continue
        else
          # The upgrade did not stick, we will retry later.
          rc=121
          break
        fi
      fi
    done
  done
  # Leave a trace of a successful run.
  if [ "${rc}" -eq 0 ] && [ -n "${FLAGS_status}" ]; then
    echo "${success}" > "${FLAGS_status}"
  fi
  return "${rc}"
}

main() {
  local disk_rules_raw="${FLAGS_fw_package_dir}"/rules
  local rc=0
  local erase_tmp_dir=${FLAGS_FALSE}

  if [ ! -d "${FLAGS_tmp_dir}" ]; then
    erase_tmp_dir=${FLAGS_TRUE}
    FLAGS_tmp_dir="$(mktemp -d)"
  fi
  if [ ! -f "${disk_rules_raw}" ]; then
    log_msg "Unable to find rules file in ${FLAGS_fw_package_dir}"
    return 120
  fi
  disk_rules=${FLAGS_tmp_dir}/rules

  # remove unnecessary lines
  sed '/^#/d;/^[[:space:]]*$/d' "${disk_rules_raw}" > "${disk_rules}"

  # Unquote call to list_fixed_* as they can return several device each.
  disk_upgrade_devices "${disk_rules}" \
    $(list_fixed_ata_disks) $(list_fixed_mmc_disks) $(list_fixed_nvme_disks)
  rc=$?

  if [ "${erase_tmp_dir}" -eq "${FLAGS_TRUE}" ]; then
    rm -rf "${FLAGS_tmp_dir}"
  fi
  # Append a cksum to prevent multiple calls to this script.
  if [ "${rc}" -eq 0 ] && [ -n "${FLAGS_status}" ]; then
    cksum "${disk_rules_raw}" >> "${FLAGS_status}"
  fi
  return "${rc}"
}

# invoke main if not in test mode, otherwise let the test code call.
if [ "${FLAGS_test}" -eq "${FLAGS_FALSE}" ]; then
  main "$@"
fi
