#!/bin/sh
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script is run at postinstall phase of Chrome OS installation process.
# It checks if the currently running cr50 image is ready to accept a
# background update and if the resident trunks_send utility is capable of
# updating the H1. If any of the checks fails, the script exits, otherwise it
# tries updating the H1 with the new cr50 image.

script_name="$(basename "$0")"
script_dir="$(dirname "$0")"
pid="$$"

. "/usr/share/cros/gsc-constants.sh"
. "${script_dir}/cr50-get-name.sh"

logit() {
  # TODO(vbendeb): use proper logger invocation once logger is fixed.
  logger -t "${script_name}" --id="${pid}" -- "$@"
}

logit "Starting"

# Let's determine the best way to communicate with the Cr50.
if gsctool_cmd -f -s > /dev/null 2>&1; then
  logit "Will use /dev/tpm0"
  UPDATER="gsctool_cmd -s"
elif gsctool_cmd -f -t > /dev/null 2>&1; then
  logit "Will use trunks_send"
  UPDATER="gsctool_cmd -t"
else
  logit "Could not communicate with Cr50"
  exit 1
fi

CR50_IMAGE="$(cr50_get_name "${UPDATER}")"
if [ ! -f "${CR50_IMAGE}" ]; then
  logit "${CR50_IMAGE} not found, quitting."
  exit 1
fi

retries=0
while true; do
  output="$(${UPDATER} -u "${CR50_IMAGE}" 2>&1)"
  exit_status="$?"
  if [ "${exit_status}" -le 2 ]; then
    # Exit status values 2 or below indicate successful update, nonzero
    # values mean that reboot is required for the new version to kick in.
    logit "success (${exit_status})"

    # Callers of this script do not care about the details and consider any
    # non-zero value an error.
    exit_status=0
    break
  fi

  : $(( retries += 1 ))
  logit "${UPDATER} attempt ${retries} error ${exit_status}"
  # Log output text one line at a time, otherwise they are all concatenated
  # into a single long entry with messed up line breaks.
  echo "${output}" | while read -r line; do
    logit "${line}"
  done

  if [ "${retries}" -gt 2 ]; then
    break
  fi

  # Need to sleep for at least a minute to get around cr50 update throttling:
  # it rejects repeat update attempts happening sooner than 60 seconds after
  # the previous one.
  sleep 70
done

exit "${exit_status}"
