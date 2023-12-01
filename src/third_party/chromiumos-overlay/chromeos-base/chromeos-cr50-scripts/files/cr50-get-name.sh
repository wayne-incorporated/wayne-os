#!/bin/sh
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This helper script is sourced by init and postinstall scripts.
#

#
# cr50_get_name
#
# Find out which if the two available Cr50 images should be used. The only
# required command line parameter is the string, a command used to communicate
# with Cr50 (different invocations are used in case of init and postinstall).
#
# The output is the file name of the Cr50 image to use printed to stdout.
#

. "/usr/share/cros/gsc-constants.sh"

cr50_get_name() {
  local board_flags
  local board_id
  local ext="prod"  # Prod is a safer default option.
  local logger_tag="cr50_get_name"
  local updater="$1"

  logger -t "${logger_tag}" "updater is ${updater}"

  # Determine the type of the Cr50 image to use based on the H1's board ID
  # flags. The hexadecimal value of flags is reported by 'gsctool -i' in the
  # last element of a colon separated string of values.
  #
  # Depending on the interface used, gsctool -i output could be a muli line
  # text, make sure to pay attention to the relevant line only, which is
  # guaranteed to be the last and contains text formatted as follows:
  #
  # Board ID space: 5a5a4146:a5a5beb9:00007f80
  #
  exit_status=0
  output=$(${updater} -i 2>&1) || exit_status="$?"
  board_id="$(echo "${output}" | awk '/Board ID/ {gsub(/.*: /,""); print}')"
  board_flags="0x$(echo "${board_id}" | sed 's/.*://')"

  if [ "${exit_status}" != "0" ]; then
    logit "exit status: ${exit_status}"
    logit "output: ${output}"
  elif [ -z "${board_flags}" ]; then
    # Any error in detecting board flags will force using the prod image,
    # which the safe option.
    logger -t "${logger_tag}" "error detecting board ID flags"
  elif [ "${board_id}" = "ffffffff:ffffffff:ffffffff" ]; then
    logger -t "${logger_tag}" "board ID is erased using ${ext} image"
  else
    local pre_pvt

    # Flag bit 0x10 is the indication that this is a pre-pvt device.
    pre_pvt=$(( board_flags & 0x10 ))

    if [ "${pre_pvt}" = "16" ]; then
      ext="prepvt"
    fi
  fi

  logger -t "${logger_tag}" \
    "board_id: '${board_id}' board_flags: '${board_flags}', extension: '${ext}'"

  printf "%s.%s" "$(gsc_image_base_name)" "${ext}"
}
