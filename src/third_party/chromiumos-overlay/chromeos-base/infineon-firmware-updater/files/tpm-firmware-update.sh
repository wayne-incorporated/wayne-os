#!/bin/sh
#
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

. /usr/sbin/tpm-firmware-update-cleanup

# Status codes defined by tpm-firmware-updater.
EXIT_CODE_SUCCESS=0
EXIT_CODE_ERROR=1
EXIT_CODE_NO_UPDATE=3
EXIT_CODE_UPDATE_FAILED=4
EXIT_CODE_LOW_BATTERY=5
EXIT_CODE_NOT_UPDATABLE=6
EXIT_CODE_SUCCESS_COLD_REBOOT=8
EXIT_CODE_BAD_RETRY=9

# Minimum battery charge level at which to retry running the updater.
MIN_BATTERY_CHARGE_PERCENT=10

# Flag file indicating that a TPM firmware update has been requested.
TPM_FIRMWARE_UPDATE_REQUEST=/mnt/stateful_partition/unencrypted/preserve/tpm_firmware_update_request

# Flag file indicating to mount_encrypted that encrypted stateful should be
# preserved across TPM clear.
PRESERVATION_REQUEST=/mnt/stateful_partition/preservation_request

# Executes the updater, collects its status and prints the status to stdout.
run_updater() {
  (
    set +e
    echo "$(date -Iseconds) starting" 1>&2
    # TODO(mnissler): Add appropriate -u and -g flags once /dev/tpm0 no longer
    # requires root.
    # TODO(mnissler): Reading the VPD from flash requires CAP_SYS_ADMIN and
    # CAP_SYS_RAWIO. Figure out whether there's a way around that.
    TPM_FIRMWARE_UPDATE_MIN_BATTERY="${MIN_BATTERY_CHARGE_PERCENT}" \
      /sbin/minijail0 -c 0x220000 --ambient -e -l -n -p -r -v --uts -- \
      /bin/sh -x /usr/sbin/tpm-firmware-updater
    status=$?
    echo "$(date -Iseconds) finished with status ${status}" 1>&2
    echo "${status}" > /run/tpm-firmware-updater.status
  ) 2>>/var/log/tpm-firmware-updater.log | (
    # The updater writes progress indication in percent line-wise to stdout.
    # Wait for the first progress update before showing the message since we
    # don't want to show the message if there is no update.
    if read progress; then
      chromeos-boot-alert update_tpm_firmware
      while true; do
        chromeos-boot-alert update_progress "${progress}"
        read progress || break
      done
    fi
  ) >/dev/null

  # Read and return the updater status code. Leave the file around so the
  # send-tpm-firmware-update-metrics job can pick it up later for inclusion in
  # metrics.
  local status="$(cat /run/tpm-firmware-updater.status)"
  echo "${status:-1}"
}

wait_for_battery_to_charge() {
  local displayed_message

  while true; do
    # Recheck whether charge level is sufficient.
    local power_status="$(dump_power_status)"
    local battery_charge=$(echo "${power_status}" |
                           grep "^battery_display_percent " |
                           cut -d ' ' -f 2)
    if [ "${battery_charge%%.*}" -ge "${MIN_BATTERY_CHARGE_PERCENT}" ]; then
      break
    fi

    # Decide which message to show.
    local message
    if echo "${power_status}" | grep -Fqx "line_power_connected 1"; then
      message=update_tpm_firmware_low_battery_charging
    else
      message=update_tpm_firmware_low_battery
    fi

    # Only update the message if it changes to avoid flashing the screen.
    if [ "${message}" != "${displayed_message}" ]; then
      chromeos-boot-alert "${message}"
      displayed_message="${message}"
    fi

    sleep 1
  done
}

# Reboot and wait to guarantee that we don't proceed further until reboot
# actually happens.
reboot_here() {
  local reboot_type="$1"
  if [ "${reboot_type}" = "cold" ]; then
    # Try to request auto-booting after shutting down, but don't abort if it
    # doesn't work. Worst case, the user will need to manually press Power to
    # boot.
    ectool reboot_ec cold at-shutdown || :
    shutdown -h now
  else
    reboot
  fi
  sleep infinity
  exit 1
}

main() {
  # Check whether a firmware update has been requested, bail out if not.
  if [ ! -e "${TPM_FIRMWARE_UPDATE_REQUEST}" ]; then
    return 0
  fi

  local mode="$(cat "${TPM_FIRMWARE_UPDATE_REQUEST}")"
  case "${mode}" in
    preserve_stateful)
      # If the update mode is set to preserve stateful, put another stateful
      # preservation request for mount_encrypted in place so the TPM clear
      # happening after the installation of the update won't clobber stateful.
      # Note that in case the update fails, mount_encrypted will clear the
      # stateful preservation request on next reboot if it finds the TPM owned,
      # so it's OK to put the request file in place opportunistically.
      touch "${PRESERVATION_REQUEST}"
      ;;
    cleanup)
      # This branch should not run since cleanup is invoked early during boot
      # from chromeos_startup via the tpm-firmware-update-cleanup script. Bail
      # if ending up here erroneously.
      exit 0
      ;;
    first_boot|*)
      # Just run the updater. This is also the default so the unlikely case of a
      # request file with an absent / unknown mode gets handled.
      ;;
  esac

  # Update the request file to avoid making another updating attempt if we fail
  # and reboot.
  echo cleanup > "${TPM_FIRMWARE_UPDATE_REQUEST}"
  sync "${TPM_FIRMWARE_UPDATE_REQUEST}"

  # Run the updater in a loop so we can perform retries in case of insufficient
  # battery charge.
  local status
  while true; do
    status="$(run_updater)"
    if [ "${status}" != "${EXIT_CODE_LOW_BATTERY}" ]; then
      break;
    fi

    # Show a notification while we wait for the battery to charge.
    wait_for_battery_to_charge
  done

  case "${status}" in
    ${EXIT_CODE_SUCCESS})
      # The TPM requires a reset after update before it works again, reboot
      # accomplishes that.
      reboot_here "warm"
      ;;
    ${EXIT_CODE_SUCCESS_COLD_REBOOT})
      # In some cases, cold reboot is useful since it causes a more thorough TPM
      # reset.
      reboot_here "cold"
      ;;
    ${EXIT_CODE_UPDATE_FAILED})
      # The TPM is likely to be in an inoperational state due to the failed
      # update. If it is, we need to go through recovery anyways to retry the
      # update. Show a message to the user telling them about the failed
      # update and reboot so the firmware can determine whether recovery is
      # necessary.
      chromeos-boot-alert update_tpm_firmware_failure
      reboot_here "warm"
      ;;
    ${EXIT_CODE_NOT_UPDATABLE})
      # We have an update, but the TPM is already owned. This indicates a
      # logic error - the system should have requested a TPM clear when
      # putting the update request flag in place. Pretend nothing happened and
      # boot back into the OS.
      rm "${TPM_FIRMWARE_UPDATE_REQUEST}"
      ;;
    ${EXIT_CODE_ERROR}|${EXIT_CODE_NO_UPDATE}|${EXIT_CODE_BAD_RETRY}|*)
      # Update attempt complete, goal is to boot back into OS. Regardless of
      # result, call cleanup to make sure the system is put back into sane state
      # with the TPM clear.
      cleanup
      ;;
  esac

  exit 0
}

main "$@"
