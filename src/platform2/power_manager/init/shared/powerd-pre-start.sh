#!/bin/sh -u
# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script is shared by Upstart and systemd. All variables used by this
# script must be defined either in powerd.conf file for Upstart or
# powerd.service file for systemd.

# For Upstart create dirs and set the proper permissions.
# For systemd, systemd-tmpfiles handles this using powerd_directories.conf.
# We use the "UPSTART_RUN" variable, that is only defined by the Upstart conf
# to distinguish between these situations.
if [ -n "${UPSTART_RUN:=}" ]; then
  mkdir -p ${LOG_DIR} ${POWER_RUN_DIR} ${PREFS_DIR}
  chown -R power:power ${LOG_DIR} ${POWER_RUN_DIR} ${PREFS_DIR}
  chmod 755 ${LOG_DIR} ${POWER_RUN_DIR} ${PREFS_DIR}

  mkdir -p ${ROOT_RUN_DIR} ${ROOT_SPOOL_DIR}
fi

# Read the real maximum backlight luminance (i.e. not the value reported by
# the driver) from VPD and pass it to powerd via a pref file.
if [ -e "${VPD_CACHE_FILE}" ]; then
  MAX_NITS=$(sed -nre 's/^"panel_backlight_max_nits"="(.+)"$/\1/p' \
    <"${VPD_CACHE_FILE}")
  if [ -n "${MAX_NITS}" ]; then
    TEMP_FILE="$(mktemp --tmpdir powerd_nits.XXXXXXXXXX)"
    echo "${MAX_NITS}" >"${TEMP_FILE}"
    PREF_FILE="${PREFS_DIR}/${MAX_NITS_PREF}"
    mv "${TEMP_FILE}" "${PREF_FILE}"
    [ -x "/sbin/restorecon" ] && restorecon "${PREF_FILE}"
    chown power:power "${PREF_FILE}"
    chmod 644 "${PREF_FILE}"
  fi
fi

# Change ownership of files used by powerd.
for FILE in \
    /sys/power/pm_test \
    /proc/acpi/wakeup \
    /sys/class/backlight/*/* \
    /sys/class/leds/*:kbd_backlight/* \
    /sys/class/power_supply/*/charge_control_limit_max \
    /sys/module/printk/parameters/console_suspend \
    /sys/power/mem_sleep \
    /dev/snapshot \
    $(find /sys/devices/ -path "*/power/wakeup"); do
  # Test for existence to skip over wildcards that didn't match anything.
  if [ -e "${FILE}" ]; then
    chown power:power "${FILE}" || true
  fi
done

if [ -e "/sys/power/pm_print_times" ]; then
  echo 1 > /sys/power/pm_print_times
fi

if [ -e "/sys/power/pm_debug_messages" ]; then
  echo 1 > /sys/power/pm_debug_messages
fi

if [ -e "/usr/share/cros/init/optional/powerd-pre-start-wilco.sh" ]; then
  /usr/share/cros/init/optional/powerd-pre-start-wilco.sh || true
fi
