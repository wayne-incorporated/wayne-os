#!/bin/bash
#
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# With --disable-checks, dbus daemon behaves in an unpredictable way
# (see crbug.com/718814). We should avoid adding this again when uprevving dbus.
DBUS_EBUILD_FILES=$(echo "${PRESUBMIT_FILES}" | grep "sys-apps/dbus/.*\.ebuild")
for FILE in ${DBUS_EBUILD_FILES}; do
  if grep -q -e "--disable-checks" "${FILE}"; then
    echo "Please remove --disable-checks from dbus ebuild. (crbug.com/718814)"
    exit 1
  fi
done
