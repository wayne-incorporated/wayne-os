#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Simple script for PRESUBMIT.cfg.
if grep -q "login_manager/chrome_dev.conf$" <<< "${PRESUBMIT_FILES:-}"; then
  echo "Please don't check in changes to chrome_dev.conf." 1>&2
  exit 1
fi

exit 0
