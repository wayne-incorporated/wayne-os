#!/bin/sh
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script sets up Cr50 flash log time base, and then retrieves the Cr50
# flash log entries collected since the previous run and reports flash log
# events IDs to the UMA server.
#
# The previous run is identified by the timestamp saved in a file which
# survives reboots, updates and powerwashes.
#
# if the file does not exist, all Cr50 flash log entries are extracted and the
# timestamp of the last entry is saved.

TIMESTAMP_FILE_DIR="/mnt/stateful_partition/unencrypted/preserve"
TIMESTAMP_FILE_BASE="cr50_flog_timestamp"
TIMESTAMP_FILE="${TIMESTAMP_FILE_DIR}/${TIMESTAMP_FILE_BASE}"

script_name="$(basename "$0")"

logit() {
  logger -t "${script_name}" -- "$@"
}

die() {
  local text="$*"

  logit "Fatal error: ${text}"
  exit 1
}

. "/usr/share/cros/gsc-constants.sh"

main() {
  local exit_code
  local epoch_secs
  local prev_stamp

  if [ ! -f "${TIMESTAMP_FILE}" ]; then
    logit "${TIMESTAMP_FILE} not found, creating"
    echo 0 > "${TIMESTAMP_FILE}" || die "failed to create ${TIMESTAMP_FILE}"
  fi


  # Set Cr50 flash logger time base.
  epoch_secs="$(date '+%s')"
  gsctool_cmd -a -T "${epoch_secs}" ||
    die "Failed to set Cr50 flash log time base to ${epoch_secs}"
  logit "Set Cr50 flash log base time to ${epoch_secs}"

  prev_stamp="$(cat "${TIMESTAMP_FILE}")"

  # Log lines returned by gsctool -ML consist of the header followed by the
  # space separated bytes of the log entry . 'M' ensures the header is two colon
  # separated fields, the first field - the entry timestamp, the second field -
  # the log event ID.
  #
  # After awk processing below just the header is printed for each line.
  gsctool_cmd -a -M -L "${prev_stamp}" | sed 's/:/ /g' | while read -r entry; do
    local event_id
    local new_stamp

    # shellcheck disable=SC2086
    set -- ${entry}

    new_stamp=$1
    event_id=$2

    if [ "${event_id}" = "05" ]; then
      # If event_id is 05, which is FE_LOG_NVMEM, then adopt '200 + the first
      # byte of payload' as an new event_id, as defined as enum Cr50FlashLogs in
      # https://chromium.googlesource.com/chromium/src/+/master/tools/metrics/
      # histograms/enums.xml.
      #
      # For example, event_id=05, payload[0]=00, then new event id is 200, which
      # is labed as 'Nvmem Malloc'.
      event_id="$(printf "%x" $(( 200 + 0x$3 )))"
    fi

    metrics_client -s "$(gsc_metrics_prefix).FlashLog" "0x${event_id}"
    exit_code="$?"
    if [ "${exit_code}" = 0 ]; then
      echo "${new_stamp}" > "${TIMESTAMP_FILE}"
    else
      die "failed to log event ${event_id} at timestamp ${new_stamp}"
    fi
  done
}

main "$@"
