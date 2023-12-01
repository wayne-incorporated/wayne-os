#!/bin/sh
# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This sets the activation date to the RW_VPD of a device. Here we wait
# for a proper time sync to have taken place before setting the value
# to ensure that the time is correct.

JOB="activate_date"
FIELD_NAME="ActivateDate"
OOBE_COMPLETED_FILE="/home/chronos/.oobe_completed"

# Never run from a factory image.
if [ -f /root/.factory_test -o -f /root/.factory_installer ]; then
  exit 0
fi

# Wait for OOBE to have completed.
while [ ! -f "${OOBE_COMPLETED_FILE}" ]; do
  sleep 1
done

# Don't run if we have set the date already, we use vpd_get_value so that
# we can leverage the cached VPD file.
# This is a soft check, the activate_date script will also check the vpd
# directly to see if a date has been set.
ACTIVATE_DATE="$(vpd_get_value "${FIELD_NAME}" || :)"
if [ -n "${ACTIVATE_DATE}" ]; then
  exit 0
fi

# Wait for remote sync of clock, then write activation date. Both enrollment
# and login require network connection (and tlsdated has been fixed to sync
# immediately when the network comes up [1]), thus in practice we should never
# have to wait.
# [1] https://code.google.com/p/chrome-os-partner/issues/detail?id=38718
while true; do
  if dbus-send --system --dest=org.torproject.tlsdate --print-reply      \
      /org/torproject/tlsdate org.torproject.tlsdate.LastSyncInfo 2>&1 | \
      grep -q 'string "network"'; then
    if ! activate_date 2>&1; then
      logger -t "${JOB}" "activate_date failed."
      exit 0
    fi
    if ! dump_vpd_log --force 2>&1; then
      logger -t "${JOB}" "dump_vpd_log failed."
      exit 0
    fi
    logger -t "${JOB}" "Activation date set."
    exit 0
  fi
  sleep 200
done
