#!/bin/sh

# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Logger wrapper.
log_message() {
  logger -t temp_logger "$@"
}

# Output xx:yyC where xx is temp sensor id and yy is the actual temperature.
get_sensor_temp() {
  local zone="$1"
  local namepath=""
  local name=""
  local tempc=0
  local tempstr=""

  if [ ! -r "${zone}" ]; then
    return
  fi
  namepath="$(dirname "${zone}")/type"
  name="$(tr ' ' '_' < "${namepath}")"
  tempc=$(($(cat "${zone}") / 1000))
  tempstr=$(printf "%s:%dC" "${name}" "${tempc}")
  echo "${tempstr}"
}

# Glob all temp sensors sysfs and output temperatures with get_sensor_temp().
get_all_sensor_temps() {
  local logstr=""
  local tempstr=""

  for zone in /sys/class/thermal/thermal_zone*/temp; do
    tempstr=$(get_sensor_temp "${zone}")
    logstr="${logstr} ${tempstr}"
  done

  echo "${logstr}"
}

# Read PL1 from powercap sysfs (Intel only), output nothing otherwise.
get_pl1() {
  local pl1="/sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw"
  local pl1uw=0
  local pl1str=""

  if [ ! -r "${pl1}" ]; then
    return
  fi
  pl1uw=$(cat "${pl1}")
  pl1str=$(printf "PL1:%.3fW" "$((pl1uw))e-6")
  echo "${pl1str}"
}

main() {
  if [ $# -ne 0 ]; then
    echo "Usage: $0" >&2
    exit 1
  fi

  if [ ! -d "/sys/class/thermal/thermal_zone0" ]; then
    log_message "Exiting temp_logger, system does not have any temp sensor."
    exit 0
  fi

  while true; do
    log_message "$(get_all_sensor_temps)" "$(get_pl1)"
    sleep 60
  done
}

main "$@"
