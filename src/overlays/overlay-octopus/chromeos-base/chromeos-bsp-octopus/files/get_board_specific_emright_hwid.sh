#!/bin/sh
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. /usr/share/misc/shflags

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# EMRight EMR doesn't support power-cut-tolerant ID.
# reads panel vendor_id and product_id to determine EMRight firmware.
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
        hardware_id="${vendor_id}_${product_id}"
      fi
    fi
  done

  case "${hardware_id}" in
   "af06_288c"|"e509_08b4")
      ## af06(AUO), e509(BOE)

      echo "${hardware_id}"
      ;;
    *)
      ## Unknown hardware_id, not output anything.
  esac
}

main "$@"