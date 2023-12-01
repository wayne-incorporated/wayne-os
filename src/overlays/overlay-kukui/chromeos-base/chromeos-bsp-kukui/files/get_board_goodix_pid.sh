#!/bin/sh

# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. /usr/share/misc/shflags
. /opt/google/touch/scripts/chromeos-touch-common.sh

DEFINE_string 'device' '' "device name" 'd'

GOODIX_FW_UPDATE_USER="goodixfwupdate"
GOODIX_FW_UPDATE_GROUP="goodixfwupdate"
GOODIX_TOUCHSCREEN_HIDRAW="/dev/goodix_touchscreen_hidraw"
GDIXUPDATE="/usr/sbin/gdixupdate"

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

get_sensor_id() {
  minijail0 -u "${GOODIX_FW_UPDATE_USER}" -g "${GOODIX_FW_UPDATE_GROUP}" \
      -n -S /opt/google/touch/policies/gdixupdate.query.policy \
      "${GDIXUPDATE}" -m -d "$1" -t "$2"
}

main() {
  local touch_device_path=""
  local product_id=""
  local model=""
  local board_rev=""

  if [ -z "${FLAGS_device}" ]; then
    die "Please specify a device using -d"
  fi

  model="$(cros_config / name)"
  board_rev="$(get_platform_ver)"
  touch_device_path="${GOODIX_TOUCHSCREEN_HIDRAW}"
  product_id="${FLAGS_device##*_}"

  if [ "${model}" = "krane" ]; then
    if [ "${board_rev}" -eq "4" ] && [ "${product_id}" = "0E30" ]; then
      local sensor_id=""
      sensor_id="$(get_sensor_id "${touch_device_path}" "${product_id}")"
      sensor_id="${sensor_id#module_id:}"
      if [ "${sensor_id}" -eq "10" ]; then
        # In the krane device, we separate the 0E30 to two different
        # PID (0E30, 0E31) after the board_rev>=5. To backward compatible
        # with the old devices, override the active_product_id to force
        # the touch updater use the new PID.
        product_id="0E31"
      else
        # Return empty string if the sensor id is not 10
        product_id=""
      fi
    elif [ "${product_id}" = "0E0C" ]; then
      # Correct the wrong PID 0E0C to the 0E30
      product_id="0E30"
    fi
  fi
  echo "${product_id}"
}

main "$@"
