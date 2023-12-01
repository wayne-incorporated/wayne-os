#!/bin/sh
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

coredump_conf_path="/run/bluetooth/coredump_disabled"
sys=$1
devpath=$2

# Bluetoothd will need to write into /sys/.../device/coredump_disabled to enable
# or disable the devcoredump feature based on a chrome://flags. Give appropriate
# permissions to write.
/bin/chown bluetooth "${sys}/${devpath}/device/coredump_disabled"

# Apply the chrome flag value if available, else disable by default.
if test -f "${coredump_conf_path}"; then
    /bin/cat "${coredump_conf_path}" > \
      "${sys}/${devpath}/device/coredump_disabled"
else
    /bin/echo 1 > "${sys}/${devpath}/device/coredump_disabled"
fi
