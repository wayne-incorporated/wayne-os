#!/bin/sh

# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. /usr/share/misc/shflags

DEFINE_string 'device' '' "i2c device name" 'd'

WACOMFLASH="/usr/sbin/wacom_flash"
GET_TOUCH_HWID="-h"

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Use "wacom -h" to get the HWID stored in either the wacom bootloader
# (tried first), or the firmware (tried next by wacom_flash utility).
main() {
  # Query the touchscreen and get the hardware id (vendor_id+product_id).
  local hardware_id=""

  hardware_id="$(
    minijail0 -S /opt/google/touch/policies/wacom_flash.query.policy \
      "${WACOMFLASH}" "dummy_unused_argument" "${GET_TOUCH_HWID}" \
      "${FLAGS_device}" 2>/dev/null
  )"

  if [ "$?" -eq 0 ] && [ "${hardware_id}" != "0000_0000" ]; then
    echo "${hardware_id}"
  fi
}

main "$@"
