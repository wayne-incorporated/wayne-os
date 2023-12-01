#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# We block the UI at splash screen to check for available firmware
# updates and apply them. This script is called by `pre-ui` upstart job.

LOGGER_TAG="fwupd-at-boot"

main() {
  local ret=0

  if [ "$#" -ne 0 ]; then
    logger -t "${LOGGER_TAG}" "Too many arguments."
    return 1
  fi

  local pending
  readarray -d $'\0' pending < \
    <(find /var/lib/fwupd/pending -type f -size -100c -print0 2>/dev/null)
  if [ -z "${pending[*]}" ]; then
	return "${ret}"
  fi

  # Show boot alert.
  chromeos-boot-alert update_fwupd_firmware

  # Make sure udev is ready
  start udev-trigger

  # Explicitly start fwupd daemon without relaying on dbus activation
  # during early boot stages.
  start fwupd

  for i in "${pending[@]}"; do
    # Trigger fwupdtool-update job, which blocks until the job completes.
    /sbin/initctl emit fwupdtool-update GUID="${i##*/}" \
      PLUGIN="$(cat "${i}")" AT_BOOT="true" || ret=1
    rm "${i}"
  done

  return "${ret}"
}

main "$@"
