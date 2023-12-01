#!/bin/sh
# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# die on error.
set -e

LOGGER_TAG="control_usb_nfc_beep"

main() {
  local gpio_level=0
  local device=''
  local enable="$1"

  device=$(cros_config / name)
  if [ "${device}" != "brask" ]; then
    exit 0
  fi

  if [ "${enable}" = "1" ]; then
    gpio_level=1
  fi

  logger -t "${LOGGER_TAG}" "Set usb nfc beep to ${gpio_level}"
  ectool gpioset EN_NFC_BUZZER "${gpio_level}"
}

main "$@"
