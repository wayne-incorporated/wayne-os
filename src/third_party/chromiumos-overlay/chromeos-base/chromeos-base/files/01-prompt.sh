# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# shellcheck shell=bash

# Update the hostname in the prompt to something useful.  We use
# ${model}-rev${board_id} when a board_id is available, otherwise just ${model}.
# We do everything in a subshell in order to not leak variables to the shell.
# A special file "/run/dont-modify-ps1-for-testing" can be created for on-device
# tests which require a stable PS1 string.

if [[ ! -f /run/dont-modify-ps1-for-testing ]]; then
  PS1="$(
    hostname="$(cat /run/chromeos-config/v1/name 2>/dev/null || hostname)"
    board_id="$(crossystem board_id 2>/dev/null || true)"

    if [[ -n "${board_id}" ]]; then
      hostname+="-rev${board_id}"
    fi

    echo "${PS1//\\h/${hostname}}"
  )"
fi
