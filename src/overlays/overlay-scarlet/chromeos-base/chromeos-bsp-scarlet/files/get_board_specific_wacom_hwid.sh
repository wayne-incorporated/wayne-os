#!/bin/sh
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. /usr/share/misc/shflags

# Not used; but caller provides it.
DEFINE_string 'device' '' "i2c device name" 'd'

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Wacom EMR doesn't support power-cut-tolerant ID.
# Scarlet reads SKU strappings via the display flex cable, so we can implicitly
# determine which panel from the SKU ID.
main() {
  local sku_id
  sku_id="$(crosid -f SKU)"

  case "${sku_id}" in
    # Initial builds didn't have a SKU ID.  Assume SKU 7.
    "none")
      echo "sku7"
      ;;
    # Product IDs are the same. Just make something up.
    "0"|"6"|"7")
      echo "sku${sku_id}"
      ;;
    # We only use the MSB of SKU strappings as the panel identifier.
    # So sku2 shares the same panel as sku6.
    "2")
      echo "sku6"
      ;;
    # sku3 shares the same panel as sku7.
    "3")
      echo "sku7"
      ;;
    *)
      ## Unknown SKU.
      echo 0000_0000
  esac
}

main "$@"
