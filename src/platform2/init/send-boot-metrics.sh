#!/bin/sh
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# shellcheck disable=SC2016
GET_FIRMWARE_TIME='
  /Exiting depthcharge with code/ {
    initial_usec = $8
  }
  END {
    if (initial_usec != "")
      printf "%.2f", initial_usec / 1000000
  }
'

FIRMWARE_LOG="/sys/firmware/log"
get_firmware_time() {
  local ftime
  if [ -e "${FIRMWARE_LOG}"  ]; then
    ftime="$(awk "${GET_FIRMWARE_TIME}" "${FIRMWARE_LOG}")"
  fi
  if [ -z "${ftime}" ]; then
    # shellcheck disable=SC2154
    logger -t "${UPSTART_JOB}" "Missing timestamp in firmware log"
  fi
  echo "${ftime}"
}

# TODO(jrbarnette): The firmware-boot-time file is used by tests
# for two purposes:
#  1) by boot time tests, to estimate total boot time from power
#     on (not just from kernel startup), and
#  2) by firmware tests, to estimate how long the dev mode warning
#     screen is presented.
#
# Probably there should be another way for autotests to get boot
# time, so the code to create this file can be removed.
FIRMWARE_TIME="$(get_firmware_time)"
echo "${FIRMWARE_TIME}" >/tmp/firmware-boot-time

# usage:
#   report_disk_metrics <read-sectors> <write-sectors>
report_disk_metrics() {
  metrics_client Platform.BootSectorsRead "$1" 1 1000000 50
  metrics_client Platform.BootSectorsWritten "$2" 1 10000 50
}

# shellcheck disable=SC2046
report_disk_metrics $(
  bootstat_get_last boot-complete read-sectors write-sectors)

BOOT_COMPLETE_TIME=$(bootstat_get_last boot-complete time)
CHROME_EXEC_TIME=$(bootstat_get_last chrome-exec                         \
                                     time before "${BOOT_COMPLETE_TIME}" )
PRE_STARTUP_TIME=$(bootstat_get_last pre-startup time)
TOTAL_TIME=$(awk -v firmware_time="${FIRMWARE_TIME}"           \
                 -v boot_complete_time="${BOOT_COMPLETE_TIME}" \
                 'BEGIN {print firmware_time + boot_complete_time}'
)
SYSTEM_TIME=$(awk -v chrome_exec_time="${CHROME_EXEC_TIME}" \
                  -v pre_startup_time="${PRE_STARTUP_TIME}" \
                 'BEGIN {print chrome_exec_time - pre_startup_time}')
CHROME_TIME=$(awk -v boot_complete_time="${BOOT_COMPLETE_TIME}" \
                  -v chrome_exec_time="${CHROME_EXEC_TIME}"     \
                  'BEGIN {print boot_complete_time - chrome_exec_time }')
# Some devices don't have CrOS firmware and therefore won't have these
# metrics.
if [ -n "${FIRMWARE_TIME}" ]; then
  metrics_client -t BootTime.Total2 "${TOTAL_TIME}" 1 20000 100
  metrics_client -t BootTime.Firmware "${FIRMWARE_TIME}" 1 10000 50
fi
metrics_client -t BootTime.Kernel "${PRE_STARTUP_TIME}" 1 10000 50
metrics_client -t BootTime.System "${SYSTEM_TIME}" 1 10000 50
metrics_client -t BootTime.Chrome "${CHROME_TIME}" 1 10000 50

# Force script to return true even if the last metric failed to report.
exit 0
