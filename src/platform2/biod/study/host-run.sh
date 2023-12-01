#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This can be run or sourced, which is why we don't choose to exec the final
# launch line.

FINGER_COUNT=2
ENROLLMENT_COUNT=20
VERIFICATION_COUNT=15

PICTURE_DIR=./fpstudy-fingers
# If LOG_DIR is left empty, log to console
LOG_DIR=

FPSTUDY_VIRTENV=/tmp/virtualenv-study

# Check for required commands.
CMDS_REQUIRED=( pip3 virtualenv )
if ! which "${CMDS_REQUIRED[@]}" >/dev/null 2>&1; then
  echo "Error - Missing one or more required commands: ${CMDS_REQUIRED[*]}" >&2
  exit 1
fi

# Find the fingerprint study base directory.
study_dir="$(dirname "${BASH_SOURCE[0]}")"

# Setup New Virtualenv
rm -rf "${FPSTUDY_VIRTENV}"
if ! virtualenv -p python3 "${FPSTUDY_VIRTENV}"; then
  echo "Error - Failed to setup a python virtualenv." >&2
  exit 1
fi
# shellcheck source=/dev/null
. "${FPSTUDY_VIRTENV}/bin/activate"
if ! pip3 install -r "${study_dir}/requirements.txt"; then
  echo "Error - Failed to install python dependencies." >&2
  exit 1
fi

if [[ -n "${LOG_DIR}" ]]; then
  mkdir -p "${LOG_DIR}"
fi

PATH="${study_dir}/mock-bin:${PATH}" "${study_dir}/study_serve.py"             \
  --finger-count="${FINGER_COUNT}"                                             \
  --enrollment-count="${ENROLLMENT_COUNT}"                                     \
  --verification-count="${VERIFICATION_COUNT}"                                 \
  --picture-dir="${PICTURE_DIR}"                                               \
  --log-dir="${LOG_DIR}"                                                       \
  "$@"
