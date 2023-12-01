#!/bin/sh
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# The script provides utility for detecting whether a base is currently
# connected.

# base_connected will block for at most 5 * 0.01 = ~50ms, and some
# ectool overhead (total ~80ms, experimentally)
base_connected() {
  local logger_name="$1"
  local retries=5

  # Detect if the base is connected:
  #  - Tablet mode is used on Soraka-like devices
  #  - Base attached on Nocturne-like devices with CBAS/hammer driver.
  # The EC driver may not be immediately available, so retry 5 times
  while true; do
    : $((retries -= 1))
    if ectool mkbpget switches 2>/dev/null; then
      break
    fi
    if [ "${retries}" -lt 1 ]; then
      logger -t "${logger_name}" "Error: ectool cannot talk to the EC."
      return 1
    fi
    sleep 0.01
  done | grep -qE "(Tablet mode: OFF|Base attached: ON)"
}
