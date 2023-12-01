#!/bin/sh
#
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

TPM_FIRMWARE_UPDATE_LOCATION="/run/tpm_firmware_update_location"
TPM_FIRMWARE_UPDATE_SRK_VULNERABLE_ROCA="/run/tpm_firmware_update_srk_vulnerable_roca"

main() {
  # Record whether the SRK is vulnerable to ROCA.
  if libhwsec_client is_srk_roca_vulnerable | grep -q '^true$'; then
    touch "${TPM_FIRMWARE_UPDATE_SRK_VULNERABLE_ROCA}"
  fi

  # Write to temp file and move so the correct state appears atomically.
  local tpm_version_info ifx_upgrade_info
  tpm_version_info="$(libhwsec_client get_version_info)"
  ifx_upgrade_info="$(libhwsec_client get_ifx_field_upgrade_info)"
  if tpm-firmware-locate-update "${tpm_version_info}" "${ifx_upgrade_info}" \
                                > "${TPM_FIRMWARE_UPDATE_LOCATION}.tmp"; then
    mv "${TPM_FIRMWARE_UPDATE_LOCATION}.tmp" "${TPM_FIRMWARE_UPDATE_LOCATION}"
  else
    # If there's no update or an error, create an empty file to signal to
    # consumers that the check has completed without finding an update.
    touch "${TPM_FIRMWARE_UPDATE_LOCATION}"
  fi
}

main "$@"
