#!/bin/sh
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Change ownership of the I2C controller device node for HPS.
#
# The HPS peripheral, if present, will appear as:
#  /sys/bus/i2c/devices/i2c-GOOG0020:00
# which is a symlink to the full path, something like:
#  /sys/devices/pci0000:00/0000:00:15.2/i2c_designware.2/i2c-15/i2c-GOOG0020:00
# where i2c-GOOG0020:00 is the peripheral and
# i2c-15 is the controller to which it is attached.
# The rule in 50-hps.rules passes the above sysfs device path to the
# HPS *peripheral* in $1. We map that to its corresponding I2C *controller*
# by looking up one directory.

dev_name=/dev/"$(/usr/bin/basename "$(/usr/bin/dirname "$1")")"
/bin/chgrp hpsd "${dev_name}"
/usr/bin/chcon -t cros_hps_device "${dev_name}"
/bin/ln --symbolic "${dev_name}" /dev/i2c-hps-controller
