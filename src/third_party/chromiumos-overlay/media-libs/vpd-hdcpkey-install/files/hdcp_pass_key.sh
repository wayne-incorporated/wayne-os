#!/bin/sh -e
#
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This will
#   1. Read HDCP Key from VPD.
#   2. Pass key to DP or HDMI driver.


if [ $# -ne 1 ]; then
  echo "invalid device path"
  exit
fi

VPD_HDCP_KEY="hdcp_key_v1_4"
HDCP_SYS_PATH="/sys/$1/hdcp_key"

vpd_get_value "${VPD_HDCP_KEY}" > "${HDCP_SYS_PATH}"
