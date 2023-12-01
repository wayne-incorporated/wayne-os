#!/bin/sh
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script is run in the factory process, which sets serial number bits
# properly for cr50.

PLATFORM_INDEX=false

READ_RMA_SN_BITS="/usr/share/cros/cr50-read-rma-sn-bits.sh"
READ_BOARD_ID_BITS="/usr/share/cros/cr50-read-board-id.sh"
TPM_WRITESPACE="/usr/share/cros/tpm2-write-space.sh"
TPM_LOCKSPACE="/usr/share/cros/tpm2-lock-space.sh"

# The return codes for different failure reasons.
ERR_GENERAL=1
ERR_ALREADY_SET=2
ERR_ALREADY_SET_DIFFERENT=3
ERR_MISSING_VPD_KEY=4

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

device_has_been_rmaed() {
  if [ -n "${DRY_RUN}" ]; then
    echo "WARNING: This device has been RMAed, preventing changes to SN Bits."
  else
    die_as "This device has been RMAed, SN Bits cannot be set."
  fi
}

die_as_already_set() {
  if [ -n "${DRY_RUN}" ]; then
    echo "SN Bits have properly been set."
    exit 0
  else
    die_as "${ERR_ALREADY_SET}" "SN Bits have already been set."
  fi
}

cr50_compute_updater_sn_bits() {
  local sn="$1"

  # SN Bits are defined as the first 96 bits of the SHA256 of the serial number.
  # They are passed to the updater as a string of 24 hex characters.


  printf '%s' "${sn}" |
    openssl dgst -sha256 |
    sed -e 's/.*=[^0-9a-f]*//I' -e 's/\(.\{24\}\).*/\1/'
}

is_board_id_set_generic_tpm2() {
  local output
  if ! output="$("${READ_BOARD_ID_BITS}")"; then
    die "Failed to execute ${READ_BOARD_ID_BITS}."
  fi

  # Parse the output. E.g., 5a5a4146:a5a5beb9:0000ff00
  output="${output##* }"

  [ "${output%:*}" != "ffffffff:ffffffff" ]
}

is_board_id_set() {
  if [ "${PLATFORM_INDEX}" = true ]; then
    is_board_id_set_generic_tpm2
    return
  fi

  local output
  if ! output="$(gsctool_cmd -a -i)"; then
    die "Failed to execute gsctool_cmd -a -i"
  fi

  # Parse the output. E.g., 5a5a4146:a5a5beb9:0000ff00
  output="${output##* }"

  [ "${output%:*}" != "ffffffff:ffffffff" ]
}

has_rmaed() {
  local rma_sn_bits="$1"
  if [ "${PLATFORM_INDEX}" = false ]; then
    local device_version_and_rma_bytes="${rma_sn_bits%:*}"
    local device_rma_flags="${device_version_and_rma_bytes#*:}"
    [ "${device_rma_flags}" != ff ]
    return
  fi

  local standalone_rma_flags="{rma_sn_bits##* }"
  [ "${standalone_rma_flags}" = 0000000000000000 ]
}

cr50_check_sn_bits() {
  local sn_bits="$1"

  local output
  if ! output="$("${READ_RMA_SN_BITS}")"; then
    die "Failed to read RMA+SN Bits."
  fi

  # The output has version and reserved bytes followed by a colon (':'), then
  # RMA flags followed by a colon and SN Bits.

  local device_version_and_rma_bytes="${output%:*}"
  local device_rma_flags="${device_version_and_rma_bytes#*:}"
  if has_rmaed "${device_rma_flags}"; then
    device_has_been_rmaed
  fi

  local device_sn_bits="${output##*:}"
  device_sn_bits="${device_sn_bits%% *}"
  if [ "${device_sn_bits}" = "ffffffffffffffffffffffff" ]; then
    # SN Bits are cleared, it's ok to go ahead and set them.
    return 0
  fi

  # Check if the SN Bits have been set differently.
  if [ "${device_sn_bits}" != "${sn_bits}" ]; then
    die_as "${ERR_ALREADY_SET_DIFFERENT}" "SN Bits have been set differently" \
      "(${device_sn_bits} vs ${sn_bits})."
  fi

  die_as_already_set
}

generic_tpm2_set_sn_bits() {
  local sn_bits="$1"
  # `0FFFFE refers to the version for generic TPM2, which has a stand-alone RMA
  # byte; `80` is a chosen value that GSC never uses.
  local SN_BITS_HEADER="0FFFFE80"

  "${TPM_WRITESPACE}" 013FFF01 "${SN_BITS_HEADER}${sn_bits}" || \
    die "Failed to write SN Bits space."

  "${TPM_LOCKSPACE}" 013FFF01 || die "Failed to lock SN Bits space."

  return 0
}

cr50_set_sn_bits() {
  local sn_bits="$1"

  if [ "${PLATFORM_INDEX}" = true ]; then
    generic_tpm2_set_sn_bits "${sn_bits}"
  else
    gsctool_cmd -a -S "${sn_bits}" 2>&1
  fi
  local status=$?
  if [ "${status}" -ne 0 ]; then
    local warning
    if [ "${status}" -gt 2 ] && is_board_id_set; then
      warning=" (BoardID is set)"
    fi
    die "Failed to set SN Bits to ${sn_bits}${warning}."
  fi
}

main() {
  if [ "$1" = -n ]; then
    DRY_RUN=Y
  fi

  local VPD_KEY=attested_device_id
  local sn
  sn="$(vpd -g "${VPD_KEY}" 2>/dev/null)"
  if [ -z "${sn}" ]; then
    die_as "${ERR_MISSING_VPD_KEY}" \
      "The RO VPD key ${VPD_KEY} must present and not empty."
  fi

  # Compute desired SN Bits, check that they can be set, and set them.

  local sn_bits
  sn_bits="$(cr50_compute_updater_sn_bits "${sn}")"

  cr50_check_sn_bits "${sn_bits}"
  if [ -n "${DRY_RUN}" ]; then
    printf "SN Bits have not been set yet"
    if is_board_id_set; then
      printf " (BoardID is set)"
    fi
    echo .
    exit 0
  fi

  cr50_set_sn_bits "${sn_bits}"
  echo "Successfully updated SN Bits for ${sn}."
}

main "$@"
