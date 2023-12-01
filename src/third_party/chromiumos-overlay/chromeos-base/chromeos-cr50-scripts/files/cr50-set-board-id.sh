#!/bin/sh
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script is run in the factory process, which sets the board id and
# flags properly for cr50.

PLATFORM_INDEX=false

GENERIC_BOARD_ID_NVRAM_READER="/usr/share/cros/tpm2-read-board-id.sh"
TPM_WRITESPACE="/usr/share/cros/tpm2-write-space.sh"
TPM_LOCKSPACE="/usr/share/cros/tpm2-lock-space.sh"

# The return codes for different failure reasons.
ERR_GENERAL=1
ERR_ALREADY_SET=2
ERR_ALREADY_SET_DIFFERENT=3
ERR_DEVICE_STATE=4

. "/usr/share/cros/gsc-constants.sh"

die_as() {
  local exit_value="$1"
  shift
  echo "ERROR: $*"
  exit "${exit_value}"
}

die() {
  die_as "${ERR_GENERAL}" "$*"
}

char_to_hex() {
  printf '%s' "$1" | od -A n -t x1 | sed 's/ //g'
}

hex_eq() {
  [ "$(printf '%d' "$1")" = "$(printf '%d' "$2")" ]
}

cr50_check_board_id_and_flag() {
  local new_board_id;
  new_board_id="$(char_to_hex "$1")"
  local new_flag="$2"
  local bid_cmd

  # Choose to use gsctool or generic tpm2 commands based on PLATFORM_INDEX.
  # It's false for gsc devices and true for generic tpm2 devices.
  # The same check is used below to choose between
  # cr50_set_board_id_and_flag and generic_tpm2_set_board_id
  if [ "${PLATFORM_INDEX}" = false ]; then
    bid_cmd="gsctool_cmd -a -i"
  else
    # Note that it is supposed to output the same data layout as
    # 'gsctool -a -i'.
    bid_cmd="${GENERIC_BOARD_ID_NVRAM_READER}"
  fi

  local exit_status=0
  local output
  output="$(${bid_cmd})" || exit_status="$?"
  if [ "${exit_status}" != "0" ]; then
    die "Failed to execute \"${bid_cmd}\", return code ${exit_status}"
  fi

  # Parse the output. E.g., 5a5a4146:a5a5beb9:0000ff00
  output="${output##* }"

  if [ "${output%:*}" = "ffffffff:ffffffff" ]; then
    # Board ID is type cleared, it's ok to go ahead and set it.
    return 0
  fi

  # Check if the board ID has been set differently.
  # The first field is the board ID in hex. E.g., 5a5a4146
  local board_id="${output%%:*}"
  if [ "${board_id}" != "${new_board_id}" ]; then
    die_as "${ERR_ALREADY_SET_DIFFERENT}" "Board ID has been set differently."
  fi

  # Check if the flag has been set differently
  # The last field is the flag in hex. E.g., 0000ff00
  local flag=0x"${output##*:}"
  local desc=""
  # The 0x4000 bit is the difference between MP and whitelabel flags. Factory
  # scripts can ignore this mismatch if it's the only difference between the set
  # board id and the new board id.
  if hex_eq "$((flag ^ new_flag))" "0x4000"; then
    desc="Whitelabel mismatch."
  elif ! hex_eq "${flag}" "${new_flag}"; then
    die_as "${ERR_ALREADY_SET_DIFFERENT}" "Flag has been set differently."
  fi
  die_as "${ERR_ALREADY_SET}" "Board ID and flag have already been set. ${desc}"
}

cr50_set_board_id_and_flag() {
  local board_id="$1"
  local flag="$2"

  local updater_arg="${board_id}:${flag}"
  if ! gsctool_cmd -a -i "${updater_arg}" 2>&1; then
    die "Failed to update with ${updater_arg}"
  fi
}

reverse_endian() {
  local v=$1
  echo "${v}" | tac -rs .. | tr -d '\n'
}

generic_tpm2_set_board_id() {
  local flag="$2"

  local p1
  p1="$(char_to_hex "$1")"
  # the second 4 bytes are bitwise inverse of the first part.
  local p2="0x${p1}"
  p2="$(printf '%X' "$(( ~ p2 & 0xFFFFFFFF ))" )"

  flag="$(printf '%X' "$(( flag ))" )"

  p1="$(reverse_endian "${p1}")"
  p2="$(reverse_endian "${p2}")"
  flag="$(reverse_endian "${flag}")"
  flag="${flag}0000"

  local board_id="${p1}${p2}${flag}"

  "${TPM_WRITESPACE}" 013FFF00 "${board_id}" || die "Failed to write board id space."

  "${TPM_LOCKSPACE}" 013FFF00 || die "Failed to lock board id space."
}

# Check if a string version has a valid format.
# Convert string version representation into ordinal number.
# String version representation is of the form
#
# <epoch>.<major>.<minor>
#
# Where each field is a number
check_version_valid() {
  local version="$1"

  if ! echo "${version}" | grep -qE "^([0-9]+\.){2}[0-9]+" ; then
    die "Wrong version string format: ${version}"
  fi
}

# Convert string version representation into ordinal number.
# This function verifies the version format and prints a single number which is
# calculated as
#
# (epoch * 256 + major) * 256 + minor
version_to_ord() {
  local version="$1"
  local epoch
  local major
  local minor
  local scale=256

  check_version_valid "${version}"

  epoch="$(echo "${version}" | cut -d '.' -f 1)"
  major="$(echo "${version}" | cut -d '.' -f 2)"
  minor="$(echo "${version}" | cut -d '.' -f 3)"
  echo "$(( (epoch * scale + major) * scale + minor ))"
}

# Check if a string version is a prod image.
# This function verifies the version format and checks if the major version is
# an odd number.
check_version_prod() {
  local version="$1"
  local major

  check_version_valid "${version}"

  major="$(echo "${version}" | cut -d '.' -f 2)"
  return $(( (major & 1) ^ 1 ))
}

# Exit if cr50 is running an image with a version less than the given prod or
# prepvt version. The arguments are the lowest prod version the DUT should be
# running, the lowest prepvt version the DUT should be running, and a
# description of the feature.
check_cr50_support() {
  local target_prod="$1"
  local target_prepvt="$2"
  local desc="$3"
  local output
  local exit_status=0
  local rw_version
  local target

  output="$(gsctool_cmd -a -f -M 2>&1)" || exit_status="$?"
  if [ "${exit_status}" != "0" ]; then
    die "Failed to get the version."
  fi

  rw_version="$(echo "${output}" | grep RW_FW_VER | cut -d = -f 2)"
  if check_version_prod "${rw_version}"; then
    target="${target_prod}"
  else
    target="${target_prepvt}"
  fi

  if [ "$(version_to_ord "${rw_version}")" -lt \
       "$(version_to_ord "${target}")" ]; then
    die "Running cr50 ${rw_version}. ${desc} support was added in .${target}."
  fi
}

# Only check and set Board ID in normal mode without debug features turned on
# and only if the device has been finalized, as evidenced by the software
# write protect status. In some states scripts should also skip the reboot
# after update. If the SW WP is disabled or the state can not be gotten, skip
# reboot. Use ERR_GENERAL when the board id shouldn't be set. Use the
# ERR_DEVICE_STATE exit status when the reboot and setting the board id should
# be skipped
check_device() {
  local exit_status=0
  local flash_status=""

  flash_status=$(flashrom -p host --wp-status 2>&1) || exit_status="$?"
  if [ "${exit_status}" != "0" ]; then
    echo "${flash_status}"
    exit_status="${ERR_DEVICE_STATE}"
  elif ! crossystem 'mainfw_type?normal' 'cros_debug?0'; then
    echo "Not running normal image."
    exit_status="${ERR_GENERAL}"
  elif echo "${flash_status}" | grep -q 'write protect is disabled'; then
    echo "write protection is disabled"
    exit_status="${ERR_DEVICE_STATE}"
  fi
  exit "${exit_status}"
}

main() {
  local exit_status=0
  local phase=""
  local rlz=""

  case "$#" in
    1)
      phase="$1"
      ;;
    2)
      phase="$1"
      rlz="$2"
      ;;
    *)
      die "Usage: $0 phase [board_id]"
  esac

  local flag=""
  case "${phase}" in
    "check_device")
      # The check_device function will not return
      check_device
      ;;
    "whitelabel_pvt_flags")
      # Whitelabel flags are set by using 0xffffffff as the rlz and the
      # whitelabel flags. Cr50 images that support partial board id will ignore
      # the board id type if it's 0xffffffff and only set the flags.
      # Partial board id support was added in 0.3.24 and 0.4.24. Before that
      # images won't ever ignore the type field. They always set
      # board_id_type_inv to ~board_id_type. Trying the whitelabel_flags command
      # on these old images would blow the board id type in addition to the
      # flags, and prevent setting the RLZ later. Exit here if the image doesn't
      # support partial board id.
      if [ "$(gsc_name)" = "cr50" ]; then
        check_cr50_support "0.3.24" "0.4.24" "partial board id"
      fi

      rlz="0xffffffff"
      flag="0x3f80"
      ;;
    "whitelabel_dev_flags")
      # See "whitelabel_pvt_flags" for more details.
      if [ "$(gsc_name)" = "cr50" ]; then
        check_cr50_support "0.3.24" "0.4.24" "partial board id"
      fi

      rlz="0xffffffff"
      # Per discussion in b/179626571
      flag="0x3f7f"
      ;;
    "whitelabel_pvt")
      flag="0x3f80"
      ;;
    "whitelabel_dev")
      # Per discussion in b/179626571
      flag="0x3f7f"
      ;;
    "unknown")
      flag="0xff00"
      ;;
    "dev" | "proto"* | "evt"* | "dvt"*)
      # Per discussion related in b/67009607 and
      # go/cr50-board-id-in-factory#heading=h.7woiaqrgyoe1, 0x8000 is reserved.
      flag="0x7f7f"
      ;;
    "mp"* | "pvt"*)
      flag="0x7f80"
      ;;
    *)
      die "Unknown phase (${phase})"
      ;;
  esac

  # To provision board ID, we use RLZ brand code which is a four letter code
  # (see full list on go/crosrlz) from cros_config.
  if [ -z "${rlz}" ] ; then
    rlz="$(cros_config / brand-code)" || exit_status="$?"
    if [ "${exit_status}" != "0" ]; then
      die "cros_config returned non-zero."
    fi
  fi
  case "${#rlz}" in
    0)
      die "No RLZ brand code assigned yet."
      ;;
    4)
      # Valid RLZ are 4 letters
      ;;
    10)
      if ! hex_eq "${rlz}" "0xffffffff"; then
        die "Only support erased hex RLZ not ${rlz}."
      fi
      ;;
    *)
      die "Invalid RLZ brand code (${rlz})."
      ;;
  esac

  cr50_check_board_id_and_flag "${rlz}" "${flag}"

  if [ "${PLATFORM_INDEX}" = false ]; then
    cr50_set_board_id_and_flag "${rlz}" "${flag}"
  else
    generic_tpm2_set_board_id "${rlz}" "${flag}"
  fi
  echo "Successfully updated board ID to '${rlz}' with phase '${phase}'."
}

main "$@"
