#!/bin/sh

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

logit() {
  logger -t "update-ax211" "$@"
}

# Temporary workaround for b/281885024.
# TODO(b/281885024): Remove the extra reboot once b/281885024 has been fixed.
# The host needs to be rebooted on the first boot after upgrading AX211 from
# Core74 or earlier to Core76+.
main() {
  local iwlwifi_skip_reboot='/var/lib/misc/iwlwifi_skip_reboot'
  local lab_file='/mnt/stateful_partition/.labmachine'
  local reboot_file='/tmp/force_reboot_after_fw_update'
  if [ -f "${iwlwifi_skip_reboot}" ] || [ -f "${lab_file}" ]; then
    # Don't reboot lab machines since they get powerwashed and provisioned
    # with older images all the time.
    logit "Skipping iwlwifi forced reboot."
  else
    logit "Wait until iwlwifi OTP burn has completed."
    chromeos-boot-alert update_firmware
    # We can't check exactly that the burn has finished since at that point
    # the chipset may not be responsive. 20s is plently, it should take <2s
    # after the 5-10s it takes to start WiFi and apply the firmware update.
    sleep 20
    # Create a file on stateful that will persist across reboots to avoid
    # bootloops.
    touch "${iwlwifi_skip_reboot}" # croslint: disable: keeping state is WAI.
    touch "${reboot_file}" # croslint: disable: file deleted by the caller.
  fi
}

main "$@"
