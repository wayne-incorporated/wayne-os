#!/bin/sh
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. /usr/share/misc/shflags

# Not used; but caller provides it.
DEFINE_string 'device' '' "i2c device name" 'd'

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"


# Wacom EMR doesn't support power-cut-tolerant ID.
# Reads panel vendor_id and product_id to determine wacom firmware.
main() {
  local vendor_id
  local product_id
  local hardware_id
  local oem_id
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
  oem_id="$(cros_config / oem-id)"

  case "${hardware_id}" in
    "745e_2c34"|"832c_0508")
      ## 745e(Wistron), 832c(KDC)

      # The same hardware_id may be returned for projects with two different
      # OEMs. To prevent collisions, Nami wacom firmware files are prefixed
      # with the oem-id.
      # This would break product_id parsing, but that is never used for Nami
      # projects anyway.
      echo "oem${oem_id}_${hardware_id}"
      ;;
    *)
      ## Unknown hardware_id, not output anything.
  esac
}

main "$@"
