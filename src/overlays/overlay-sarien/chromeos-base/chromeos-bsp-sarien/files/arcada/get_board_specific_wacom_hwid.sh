#!/bin/sh
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script reads panel vendor_id and product_id to determin wacom touch
# screen config and return wacom hardware_id to caller
# return value: wacom hardware_id

. /usr/share/misc/shflags

# Not used; but caller provides it.
DEFINE_string 'device' '' "i2c device name" 'd'

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Wacom AES doesn't support power-cut-tolerant ID.
# Arcada reads panel vendor_id and product_id to determine wacom firmware.
main() {
  local vendor_id
  local product_id
  local hardware_id

  for path in /sys/class/drm/*eDP*/edid; do
    # Check path is exist, otherwise hexdump hits error
    if [ -e "${path}" ]; then
      # EDID 0x8-0x9 is Manufacturer ID
      vendor_id="$(hexdump -n 0xc "${path}" | awk '{print $6}' | sed '/^\s*$/d')"
      # EDID 0xa-0xb is Manufacturer product code
      product_id="$(hexdump -n 0xc "${path}" | awk '{print $7}' | sed '/^\s*$/d')"
      if [ -n "${product_id}" ]; then
        hardware_id="${vendor_id}-${product_id}"
      fi
    fi
  done

  case "${hardware_id}" in
    "af06-632d") # af06(AUO)
      echo "2d1f_4944"  # wacom hardware_id = VID_PID
    ;;
    "e430-05dc") # e430(LGD)
      echo "2d1f_4945"  # wacom hardware_id = VID_PID
    ;;
    "ae0d-1382") # ae0d(INO)
      echo "2d1f_4946"  # wacom hardware_id = VID_PID
    ;;
    "e509-08dd") # e509(BOE)
      echo "2d1f_4a01"  # wacom hardware_id = VID_PID
    ;;
    *)
      ## Unknown hardware_id, don't ouput anything.
  esac
}

main "$@"
