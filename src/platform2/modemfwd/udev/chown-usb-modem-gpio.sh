#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# 94-usb-modem-gpio.rules passes the sysfs device path as $1
# GPIO DEBICE as $2, and the modem reset pin offsets as the rest.
# Different sysfs nodes are present on different hardware.
GPIO_BEING_ADDED="${1}"; shift
GPIO_DEVICE="${1}"; shift
OFFSET_LIST=("${@}")
dir_list=$(find /sys/class/gpio -type l -name "gpiochip*")
for d in ${dir_list}; do
  DEVICE=$(basename "$(readlink "${d}/device")")
  if [ "${DEVICE}" == "${GPIO_DEVICE}" ]; then
    BASE=$(cat "${d}/base")
    break
  fi
done
if [ -z "${BASE}" ]; then
  # Base not set, exiting.
  exit 0
fi
TEMP="$(basename "${GPIO_BEING_ADDED}")"
for OFFSET in "${OFFSET_LIST[@]}"; do
  MODEM_RESET_GPIO="gpio$((BASE + OFFSET))"
  if [ "${MODEM_RESET_GPIO}" == "${TEMP}" ]; then
    /bin/chown modem:modem "${GPIO_BEING_ADDED}"/direction
    /bin/chown modem:modem "${GPIO_BEING_ADDED}"/value
    break
  fi
done
