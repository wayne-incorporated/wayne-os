#!/bin/sh
# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This runs from the factory install/reset shim. This MUST be run
# from USB, in developer mode. This script contains functions to erase
# securly the disk and verify it has been erased properly.

# if used inside the test harness, 2 variables are defined:
# TEST_DELAY: to reduce the amount of time checking for the eMMC to be ready
#             again,
# TEST_FIO_OUTPUT: to send the output of fio to a known file. By default,
#             if the file is generated with $(mktemp fio_output_XXXXXX)

. /usr/share/misc/chromeos-common.sh

# Return value for partial success when strict is set.
STRICT_RETURN_VALUE=100


# Outputs the NVMe namespace block devices that belong to the given
# character device.
# Arguments:
#  - NVMe character device without preceding /dev/ (ex: nvme0)
# Outputs NVMe namespaces' block devices (ex: /dev/nvme0n1)
get_nvme_block_devs() {
  local nvme="$1"
  local block_dev
  for block_dev in /sys/block/${nvme}*; do
    echo "/dev/${block_dev##*/}"
  done
}

# Outputs the size of given NVMe character device
# Arguments:
#  - NVMe character device (ex: /dev/nvme0)
get_nvme_char_device_size() {
  local disk="$1"
  local dev_size="$(nvme id-ctrl --output-format=json "${dev}" | jq ".tnvmcap")"
  if [ ${dev_size} -eq 0 ]; then
    # This may not be exact size of the disk because there might be some
    # unused blocks.
    local blk blk_size
    for blk in $(get_nvme_block_devs "${disk##*/}"); do
      blk_size="$(blockdev --getsize64 ${blk})"
      : $(( dev_size += blk_size ))
    done
  fi
  echo "${dev_size}"
}

# Get the supported erase mode for ATA disk.
# Arguments:
#  - ATA device to query
# Outputs supported erase mode: "--security-erase" or
# "--security-erase-enhanced", empty string if not supported or unknown.
get_ata_supported_erase_mode() {
  local disk="$1"
  local func
  local supported_mode
  for func in "supported" "supported: enhanced erase"; do
    hdparm -I "${disk}" \
      | grep -A10 "^Security" \
      | grep -q "^[[:blank:]]\+${func}$"
    if [ $? -eq 0 ]; then
      if [ "${func}" = "supported" ]; then
        supported_mode="--security-erase"
      else
        supported_mode="--security-erase-enhanced"
      fi
    fi
  done
  echo "${supported_mode}"
}

# Check if the ATA device supports block erase sanitize.
# Arguments:
#  - device to query
# Return true if the operation is supported, false if not supported.
is_sata_sanitize_supported() {
  local dev="$1"
  hdparm -I "${dev}" | grep -q "BLOCK_ERASE_EXT command"
  return $?
}

# Check if the most recent sanitize operation was completed successfully
# Arguments:
#  - device to query
# This is blocking until the sanitize has finished. Return true if the most
# recent sanitize operation was successful, false otherwise.
is_sata_sanitize_successful() {
  local dev="$1"
  hdparm --sanitize-status "${disk}" \
    | grep -iq "Last Sanitize Operation Completed Without Error"
}

# Check if the NVMe device supports block erase sanitize.
# Arguments:
#  - device to query (block device or character device)
# Return true if the operation is supported, false if not supported.
is_nvme_sanitize_supported() {
  local dev="$1"
  # Check bit #1. If it is set to 1, device supports block erase sanitize.
  local sanicap=$(nvme id-ctrl --output-format=json "${dev}" \
    | jq ".sanicap")
  test $(( sanicap / 2 % 2 )) -eq 1
  return $?
}

# Check if the device is currently being sanitized.
# Arguments:
#  - device to query
# Return true if is being sanitized, false otherwise.
is_nvme_sanitize_in_progress() {
  local dev="$1"
  # Check last 3 bits of the sanitize status value. If it is set to 010, the
  # sanitize operation is in progress.
  local status=$(nvme sanitize-log "${dev}" \
    | grep "(SSTAT)" \
    | grep -oEi "(0x)?[[:xdigit:]]+$")
  test $(( status % 8 )) -eq 2
  return $?
}

# Check if the most recent sanitize operation was completed successfully
# Arguments:
#  - device to query
# Return true if the most recent sanitize operation was successful, false
# otherwise.
is_nvme_sanitize_successful() {
  local dev="$1"
  # Check last 3 bits of the sanitize status value. If it is set to 001,
  # sanitize operation was successful.
  local status=$(nvme sanitize-log "${dev}" \
    | grep "(SSTAT)" \
    | grep -oEi "(0x)?[[:xdigit:]]+$")
  test $(( status % 8 )) -eq 1
  return $?
}

# Output the progress of nvme sanitize command. This value indicates the
# fraction complete of the sanitize operation. The value is the numerator of
# the fraction complete that has 65536 as its denominator. This value is set
# to FFFFh (65536) if there is no sanitize in progress.
# Arguments:
#  - device to query
get_nvme_sanitize_progress() {
  local dev="$1"
  nvme sanitize-log "${dev}" | grep "(SPROG)" | grep -oEi "[[:xdigit:]]+$"
}

# Return useful bits of the MMC status
#
# Return some status bits that indicates if the device has completed
# outstanding commands.
#
# if 'mmc status get' fails returns 0, which is an invalid status.
get_mmc_status() {
  local status
  status=$(mmc status get "$1" | sed -nre 's/^SEND_STATUS response: (.*)/\1/p')
  # The state is defined in chapter 6.13 of eMMC rev 5.
  # Ideally, we should check that all the error bits to be set to 0.
  # Now, reading in more details, eMMC device are not garantee to be always
  # valid (see X or R mode) or some bit are reserved.
  # Therefore, we limit only to flags that are always valid:
  # bit 6: EXCEPTION_EVENT: set to 0
  # bit 8: READY_FOR_DATA: set to 1 (0 while sanitizing)
  # bit 9-12: CURRENT_STATE: set to 4 (Tran), set to 7 (Prg while sanitizing)
  printf "0x%08x\n" $((status & 0x00001F40))
}

# Erase an MMC device using firmware functions
#
# Ask the device to trim all sectors.
# Then, ask the device to physically erase all trimmed sectors.
# Arguments:
#  - block device to erase
#  - strict: if set to "1", then only returns success if sanitize successfully
#            physically erases the device when security is supported. If left
#            empty or set to "0", returns success when sanitize succeeds
#            whether security is supported or not.
secure_erase_mmc() {
  local disk="$1"
  local strict="$2"
  local delay=${TEST_DELAY:-5}
  local count
  local secure
  local rc

  # Mark all location as unused -- try secure first.
  for secure in "-s" ""; do
    blkdiscard ${secure} "${disk}"
    rc=$?
    if [ ${rc} -eq 0 ]; then
      break
    fi
  done
  if [ ${rc} -ne 0 ]; then
    echo "security not supported, just doing overwrite"
  fi

  # Physically erase unused locations.
  # 0x00000900 equals to READY_FOR_DATA=1 and CURRENT_STATE=4 (Tran)
  mmc_orig_status=$(get_mmc_status "${disk}")
  if [ "${mmc_orig_status}" != "0x00000900" ]; then
    echo "Not ready for sanitize: status ${mmc_orig_status}."
    return 1
  fi

  mmc sanitize "${disk}" || return $?

  count=120  # wait up to 10 minutes
  mmc_status="0xffffffff"
  while [ "${mmc_status}" != "${mmc_orig_status}" -a ${count} -gt 0 ]; do
    sleep "${delay}"
    mmc_status=$(get_mmc_status "${disk}")
    : $(( count -= 1 ))
  done

  if [ "${mmc_status}" != "${mmc_orig_status}" ]; then
    echo "Device is stuck sanitizing: status ${mmc_status}."
    return 1
  fi

  if [ "${strict}" = "1" ] && [ ${rc} -ne 0 ]; then
    return ${STRICT_RETURN_VALUE}
  else
    return 0
  fi
}

secure_erase_ufs() {
  local disk="$1"
  local strict="$2"
  local rc

  blkdiscard "${disk}"
  rc=$?
  if [ ${rc} -ne 0 ]; then
    echo "Failed to discard the device"
  else
    /usr/sbin/factory_ufs purge -t 600
    rc=$?
    if [ ${rc} -ne 0 ]; then
      echo "Failed to purge the device"
    fi
  fi

  if [ "${strict}" = "1" ] && [ ${rc} -ne 0 ]; then
    return ${STRICT_RETURN_VALUE}
  else
    return 0
  fi
}

# Erase an ATA device using internal firmware function
#
# To trigger the ATA SECURE ERASE function, the disk must be
# in security mode SEC4 (aka locked) or SEC5 (aka secured).
# Disks are usually in SEC1 (unsecured).
# First put the disk in SEC5 then Erase it, that put it back in SEC1.
# Arguments:
#  - block device to erase
#  - strict: if set to "1", then only returns success if enhanced security
#            erase is supported and succeeds. Security-erase does not guarantee
#            to erase unallocated sectors whereas enhanced security erase does.
#            If left empty or set to "0", returns success if any of the
#            security erase succeed.
secure_erase_sata() {
  local disk="$1"
  local strict="$2"
  local temp_password="chromeos"
  local erase_mode="$(get_ata_supported_erase_mode "${disk}")"
  local partial_success_return_val=0

  if [ "${strict}" = "1" ]; then
    partial_success_return_val=${STRICT_RETURN_VALUE}
  fi

  if is_sata_sanitize_supported "${disk}"; then
    hdparm --yes-i-know-what-i-am-doing --sanitize-block-erase "${disk}"
    is_sata_sanitize_successful "${disk}" && return 0
  fi

  if [ -n "${erase_mode}" ]; then
    hdparm --user-master u --security-set-pass \
            "${temp_password}" "${disk}" || return $?
    hdparm --user-master u "${erase_mode}" \
        "${temp_password}" "${disk}" || return $?
  else
    echo "security not supported, just doing overwrite"
  fi
  return ${partial_success_return_val}
}

# Erase an NVMe device.
#
# Use nvme sanitize if it is supported. Otherwise try nvme format with crypto
# mode, if that fails, then try to do with user data mode with a timeout
# proportional to the size of the device.
# Arguments:
#  - character device to erase
#  - strict: if set to "1", then only returns success if sanitize successfully
#            physically erases the device. If left empty or set to "0", returns
#            success if either sanitize or nvme format succeeds.
secure_erase_nvme() {
  local disk="$1"
  local strict="$2"
  local ses_user="1"  # 0: no secure, 1: user data erase, 2: cryptographic erase
  local ses_crypto="2"
  local base_timeout_in_ms=$(( 60 * 1000 )) # base timeout for 1 minute
  local dev_size="$(get_nvme_char_device_size "${disk}")"
  local bytes_per_ms=$(( 100 * 1024 )) # 100 MB/s
  # Maximum time without any progress during sanitize operation
  local sanitize_timeout_in_sec=$(( 20 * 60 )) # sanitize timeout for 20 minutes
  # Maximum time to finish format operation. Let timeout be proportional to the
  # size of device.
  local format_timeout_in_ms=$(( base_timeout_in_ms + dev_size / bytes_per_ms ))
  local progress current_progress
  # "During a sanitize operation, the host may periodically examine the
  # Sanitize Status log page to check for progress, however, the host
  # should limit this polling (e.g., to at most once every several minutes)
  # to avoid interfering with the progress of the sanitize operation itself."
  # See section 8.15 in
  # https://www.nvmexpress.org/wp-content/uploads/NVM_Express_Revision_1.3.pdf
  # Because of the reason above need to sleep and check the progress during
  # sanitize operation. We use 10 seconds for sleeping because the device we
  # tested this code on executes the command quite fast. The whole full disk
  # wipe process takes a lot of time so we don't want to increase it even more
  # by picking a larger value.
  local sleep_time_in_sec=10

  # Sanitize is preferred over format because it guarantees physical data
  # destruction.
  if is_nvme_sanitize_supported "${disk}"; then
    nvme sanitize "${disk}" --ause --sanact=0x02
    count="${sanitize_timeout_in_sec}"
    while [ ${count} -gt 0 ] && is_nvme_sanitize_in_progress "${disk}"; do
    # See the comment above.
      sleep "${sleep_time_in_sec}"
      current_progress="$(get_nvme_sanitize_progress "${disk}")"
      if [ "${progress}" = "${current_progress}" ]; then
            : $(( count -= sleep_time_in_sec ))
      else
        count="${sanitize_timeout_in_sec}"
      fi
      progress="${current_progress}"
    done
    is_nvme_sanitize_successful "${disk}" && return 0

    # If block erase sanitize operation fails, issue sanitize command with the
    # 'Exit Failure Mode' action to recover from failure.
    nvme sanitize "${disk}" --sanact=0x01
    count="${sanitize_timeout_in_sec}"
    progress=0
    while [ ${count} -gt 0 ] && is_nvme_sanitize_in_progress "${disk}"; do
    # Check if the sanitize command executed before continuing.
    # Also see the comment above.
      sleep "${sleep_time_in_sec}"
      current_progress="$(get_nvme_sanitize_progress "${disk}")"
      if [ "${progress}" = "${current_progress}" ]; then
            : $(( count -= sleep_time_in_sec ))
      else
        count="${sanitize_timeout_in_sec}"
      fi
      progress="${current_progress}"
    done
  fi

  # If strict is set to 1, only sanitize should return success.
  # We want to be able to distinguish between the successes in strict mode
  # in order to inform users if their device is physically erased or not.
  local success_return_value=0
  if [ "${strict}" = "1" ]; then
    success_return_value=${STRICT_RETURN_VALUE}
  fi

  # Format with crypto mode
  nvme format "${disk}" --ses "${ses_crypto}" && return ${success_return_value}

  # Format with userdata mode
  # 0xffffffff means format all namespaces of the given character device.
  nvme format "${disk}" --namespace-id=0xffffffff --ses "${ses_user}" \
    --timeout "${format_timeout_in_ms}"
  local return_val=$?
  test ${return_val} -eq 0 && return ${success_return_value}
  return ${return_val}
}

# Erase a device using its internal firmware function.
#
# Arguments:
#  - device to erase ("/dev/sda", "/dev/mmcblk0", "/dev/nvme0").
#  - strict: if set to 1 then only returns success if the physical data
#            destruction is guaranteed by the command set that is used. If unset
#            or set to "0", returns success if either physical data destruction
#            is guaranteed or not.
# Returns:
#  0 if the erase is either not supported or completed.
#  !0 if the erase process could not complete or failed.
secure_erase() {
  local disk="$1"
  local strict="$2"
  local disk_type=$(get_device_type "${disk}")
  # Identify if MMC or SATA.
  case "$disk_type" in
    MMC)
      secure_erase_mmc "${disk}" "${strict}"
    ;;
    ATA)
      secure_erase_sata "${disk}" "${strict}"
    ;;
    NVME)
      secure_erase_nvme "${disk}" "${strict}"
    ;;
    UFS)
      secure_erase_ufs "${disk}" "${strict}"
    ;;
    *)
      echo "Unable to identify the type of disk: -${disk_type}-"
      return 1
  esac
}

# Use fio to write/verify a pattern.
#
# The first and last 1M of the disk are zeroed, the rest is written
# with a random patter fio can verify latter.
#
# Argument
#  - disk: the device to erase
#  - disk_size: the size of the device
#  - disk_op: "write" to write over the SSD, "verify" to check the SSD
#             has been overwritten properly, "verify_disk_wipe" to check
#             the SSD has been zeroed.
# Returns:
#  fio error code if fio could run, 1 otherwise.
perform_fio_op() {
  # Globals, used by factory_secure.fio
  local disk="$1"
  local disk_size="$2"
  local disk_op="$3"

  local dev_main_area_end=$(( ${disk_size} - 1048576 ))
  local block_size=1048576
  local fio_err=0
  local fio_output="${TEST_FIO_OUTPUT}"
  local fio_regex='/^(secure|fio)/s/.* err= *([[:digit:]]+).*/\1/p'
  local input

  export FIO_DEV="${disk}"
  export FIO_DEV_MAIN_AREA_SIZE=$(( ${disk_size} - 2097152 ))
  export OFFSET="1m"
  export VERIFY="md5"

  if [ -z "${fio_output}" ]; then
    fio_output="$(mktemp -t fio_output_XXXXXX)"
  fi
  case "$disk_op" in
    write)
      export FIO_VERIFY_ONLY=0
      # Erase the begining an the end of the drive. Write random first
      # to ensure the data is scrambled.
      for input in "urandom" "zero"; do
        dd bs="${block_size}" of="${disk}" oflag=dsync iflag=fullblock \
            if=/dev/${input} count=1
        dd bs="${block_size}" of="${disk}" oflag=dsync iflag=fullblock \
            if=/dev/${input} seek=$(( dev_main_area_end / ${block_size} ))
      done
      ;;
    verify)
      export FIO_VERIFY_ONLY=1
      ;;
    verify_disk_wipe)
      export FIO_VERIFY_ONLY=1
      export VERIFY="pattern"
      export FIO_DEV_MAIN_AREA_SIZE=${disk_size}
      export OFFSET="0"
      ;;
    *)
      echo "Unsupported operation: -${disk_op}-"
      return 1
  esac

  local fio_script="$(mktemp -t fio_config_XXXXXX)"
  cat >"${fio_script}" <<HERE
[secure]
filename=\${FIO_DEV}
ioengine=libaio
iodepth=32
direct=1
readwrite=write
bs=256k

offset=\${OFFSET}
size=\${FIO_DEV_MAIN_AREA_SIZE}
do_verify=1
verify=\${VERIFY}
verify_pattern=0x0
verify_only=\${FIO_VERIFY_ONLY}
HERE
  # Write a pattern on the media for future verification.
  # fio configuration file use DEV, DEV_MAIN_AREA_SIZE and VERIFY_ONLY.
  fio "${fio_script}" --output "${fio_output}" --aux-path="${TMPDIR:-/tmp}"
  rm -f "${fio_script}"
  fio_err=$(sed -nr "${fio_regex}" "${fio_output}")
  if [ -z "${fio_err}" ]; then
    echo "-- output of fio not understood --"
    cat "${fio_output}"
    fio_err=1
  elif [ ${fio_err} -ne 0 ]; then
    cat "${fio_output}"
    if [ $FIO_VERIFY_ONLY -eq 0 ]; then
      echo "-- writing pattern failed --"
      echo "The storage device is not working properly."
    else
      # Check if we fail to read the device, or the pattern is wrong.
      echo "-- verifying pattern failed --"
      if [ ${fio_err} -eq 84 ]; then
        echo -n "The storage device has either been tampered with or "
        echo "not securely erased properly."
      else
        echo "Storage device broken: unable to read some sector from it."
      fi
    fi
  else
    rm "${fio_output}"
  fi
  return ${fio_err}
}
