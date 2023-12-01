#!/bin/bash
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. /usr/share/misc/shflags || exit 1

# The USB type-A port number detected by udev rule.
DEFINE_string 'port' '' "usb type-A port" 'p'
DEFINE_boolean 'inhibit' "${FLAGS_FALSE}" "inhibit charge" 'i'

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# die on error.
set -e

LOGGER_TAG="control_usb_charge_mode"

main() {
  local inhibit=0
  local enabled_device=(blorb droid)
  local device=''

  if [[ "${FLAGS_port}" != "0" && "${FLAGS_port}" != "1" ]]; then
    echo "Port is not in legal range - ${FLAGS_port}"
    exit 1
  fi

  if [[ "${FLAGS_inhibit}" = "${FLAGS_TRUE}" ]]; then
    inhibit=1
  fi

  device="\b$(cros_config / name)\b"

  if [[ ! "${enabled_device[*]}" =~ ${device} ]]; then
    exit 0
  fi

  logger -t "${LOGGER_TAG}" "control inhibit charge of port ${FLAGS_port} to ${inhibit}"
  ectool usbchargemode "${FLAGS_port}" 2 "${inhibit}"
}

main "$@"
