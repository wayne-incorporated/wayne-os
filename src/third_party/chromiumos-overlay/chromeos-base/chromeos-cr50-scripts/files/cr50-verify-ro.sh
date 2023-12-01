#!/bin/bash
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script provides user interface to the 'open box RMA' procedure which
# verifies integrity of the RO areas of the RMAed device's AP and EC firmware.
#
# The script is run on a secure Chrome OS device which is connected with SuzyQ
# cable to the RMAed device (also referred to as "device under test" a.k.a.
# DUT).
#
# The script checks the Cr50 version run on the DUT and updates it if
# necessary. After that this script invokes gsctool to perform actual RO
# verification.

. "/usr/share/cros/gsc-constants.sh"

# Remember pid of the top level script to be able to terminate it from
# subprocesses.
TOP_PID="$$"

trap "exit 1" TERM

# Terminal decorations for error and success messages.
V_BOLD_RED="$(tput bold; tput setaf 1)"
V_BOLD_GREEN="$(tput bold; tput setaf 2)"
V_VIDOFF="$(tput sgr0)"

die() {
  local text="$*"

  echo "${V_BOLD_RED}${text}${V_VIDOFF}" >&2
  kill -s TERM "${TOP_PID}"
}

# Retrieve board ID and flags values from the H1 on the DUT.
#
# Output of 'gsctool -i' contains a line of the following format:
#
# Board ID space: <hex board ID>:~<hex board id>:<hex flags>
#
# The <hex board ID> value is included twice, straight and inverted.
#
# This function verifies that board ID value is valid and prints a string
# consisting of board ID and flags, each prepended with '0x'.
get_chip_bid_values() {
  local flags
  local xor

  IFS=' ' read -r -a flags <<< "$(gsctool_cmd -i |
    awk -F':' '
      /Board ID space: / {
        sub(" ", "", $2);
        print "0x"$2" 0x"$3" 0x"$4
      }')"

  if [[ "${#flags[@]}" != 3 ]]; then
    die "Wrong format of chip flags: ${flags[*]}"
  fi

  # verify that board ID is intact
  xor=$(( ( flags[0] ^ ~flags[1] ) & 0xffffffff ))
  if [[ ${xor} != 0 ]]; then
    die "Invalid chip board ID value bid ${flags[0]}, ~bid ${flags[1]}"
  fi

  # Echo Board ID and flags
  echo "${flags[0]} ${flags[2]}"
}

# Retrieve RLZ from the H1 on the DUT.
#
# Output of 'gsctool -i -M' contains a line of the following format:
#
# BID_RLZ=<RLZ String>
#

get_chip_rlz_value() {
  gsctool_cmd -i -M | grep BID_RLZ | sed -e 's/BID_RLZ=//g;'
}

# Retrieve Cr50 binary's board ID and flags values.
#
# Ouput of 'gsctool -b cr50.bin' contains a line of the following format:
#
# RO_A:0.0.10 RW_A:0.0.24[<board ID>:<hex board ID mask>:<hex flags] ...
#
# For the purposes of this script RW_A and RW_B sections are guaranteed to
# have the same board ID programmed in their respective headers.
#
# The actual <board ID> value could be expressed as an 8 symbol hex or a 4
# symbol ASCII (the RLZ code). This function converts the ASCII into hex if
# necessary and prints out a string consisting of hex board ID, hex board ID
# mask and hex flags, all prepended with '0x'.
get_image_bid_values() {
  local image="${1}"
  local flags

  IFS=':' read -r -a flags <<< "$(gsctool_cmd -b "${image}" |
     awk '{
       if (match($0, /\[[^\]]+\]/)) {
         print substr($0, RSTART + 1, RLENGTH - 2)
       }
     }')"

  if [[ "${#flags[@]}" != 3 ]]; then
    die "Wrong format of image flags: ${flags[*]}"
  fi

  if [[ "${#flags[0]}" == 4 ]]; then
    # Convert ASCII board name into hex.
    flags[0]="$(printf "%s" "${flags[0]}" | hexdump -v -e '/1 "%02X"')"
  fi
  echo "${flags[@]/#/0x}"
}

# Update DUT Cr50 firmware to the passed in image.
update_dut() {
  local chip_bid
  local chip_flags
  local chip_values
  local image_bid
  local image_file
  local image_flags
  local image_mask
  local image_values

  image_file="$1"

  # Retrieve board ID header fields of the image file.
  IFS=' ' read -r -a image_values <<< "$(get_image_bid_values "${image_file}" )"

  image_bid="${image_values[0]}"
  image_mask="${image_values[1]}"
  image_flags="${image_values[2]}"

  # Retrieve board ID fields of the H1 on the DUT.
  read -r -a chip_values <<< "$(get_chip_bid_values)"

  chip_bid="${chip_values[0]}"
  chip_flags="${chip_values[1]}"

  # Verify that board ID of the image is suitable for the chip.
  match=$(( (image_bid & image_mask) == (chip_bid & image_mask) ))
  if [[ ${match} != 1 ]]; then
    die "Image board ID ${image_bid} and mask ${image_mask} " \
        "incompatible with chip board ID ${chip_bid}"
  fi

  # Verify that flags of the image are compatible with the chip.
  match=$(( (image_flags & chip_flags) == image_flags ))
  if [[ ${match} != 1 ]]; then
    die "Image flags ${image_flags} incompatible with chip flags ${chip_flags}"
  fi

  gsctool_cmd "${image_file}"
}

# Convert string version representation into ordinal number.
#
# String version representation is of the form
#
# <epoch>.<major>.<minor>
#
# Where each field is a number. This function verifies the format and prints a
# single number which is calculated as
#
# (epoch * 256 + major) * 256 + minor
version_to_ord() {
  local version="$1"
  local split_version
  local scale=256

  if ! echo -n "${version}" | grep -qzE "^([0-9]+\.){2}[0-9]+$" ; then
    die "Wrong version string format: ${version}"
  else
    IFS='.' read -r -a split_version <<< "${version}"
    echo "$(( (split_version[0] * scale + split_version[1]) * scale
        + split_version[2] ))"
  fi
}

# Compare two version strings and return 0 (i.e. 'success' in bash terms) if
# the first version expressed as an integer is lower than the second one.
update_needed() {
  local dut_version="$1"
  local image_version="$2"
  local dut_ord
  local image_ord

  dut_ord="$(version_to_ord "${dut_version}")"
  image_ord="$(version_to_ord "${image_version}")"

  return $(( dut_ord >= image_ord ))
}

# The two arguments are the Cr50 image file of the lowest
# version DUT should be running, and the RO verification
# descriptors database file.
main() {
  local dut_rw_version
  local image_rw_version
  local new_image
  local ro_descriptions
  local rlz

  new_image="$1"
  ro_descriptions="$2"

  if [[ "$#" != 2 || ! -f "${new_image}" || ! -d "${ro_descriptions}" ]]; then
    die "Two parameters are required: name of the Cr50 image file"\
        "and name of the RO verification descriptors database file"
  fi

  # Retrieve Cr50 version running on the DUT. Reported in 'gsctool -f' output
  # as RW <epoch>.<major>.<minor>
  dut_rw_version="$(gsctool_cmd -f | awk '/^RW / {print $2}')"
  if [[ -z "${dut_rw_version}" ]]; then
    die "Failed to retrieve DUT Cr50 version. Is DUT connected?"\
        "You may need to flip suzy-q cable if DUT is already attached."
  fi

  # Retrieve RW Cr50 version of the supplied image file. Reported in 'gsctool
  # -b' output as
  #
  # RO_A:<epoch>.<major>.<minor> RW_A:<epoch>.<major>.<minor>:[...
  #
  # RW_A and RW_B versions are expected to match for the purposes of this
  # script.
  image_rw_version="$(gsctool_cmd -b "${new_image}" | awk '
    /^RO_A/ {
      match($2, /:.*\[/);
      print substr($2, RSTART + 1, RLENGTH - 2)
    }')"

  # Check is the image running on the DUT is older than the supplied image, and
  # if so - update the DUT.
  if update_needed "${dut_rw_version}" "${image_rw_version}"; then
    echo "Updating dut from ${dut_rw_version} to ${image_rw_version}"
    update_dut "${new_image}"
    echo "Waiting for the DUT to restart"
    sleep 5 # Let it reboot.
    echo "Verifying that update succeeded"
    dut_rw_version="$(gsctool_cmd -f | awk '/^RW / {print $2}')"
    if update_needed "${dut_rw_version}" "${image_rw_version}"; then
      die "Failed to update DUT to version ${image_rw_version}"
    fi
  fi

  # Retrieve board RLZ
  rlz="$(get_chip_rlz_value)"

  # Run RO verification and report results.
  if gsctool_cmd -O "${ro_descriptions}/verify_ro_${rlz}.db"; then
    echo "${V_BOLD_GREEN}Hash verification succeeded${V_VIDOFF}"
    exit 0
  else
    echo "${V_BOLD_RED}Hash verification failed${V_VIDOFF}"
    exit 1
  fi
}

main "$@"
