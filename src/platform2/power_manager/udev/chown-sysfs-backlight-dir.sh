#!/bin/sh
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Change ownership of relevant nodes in a sysfs backlight directory
# so powerd can use them.

# 99-powerd-permissions.rules passes the sysfs device path as $1.
# Different sysfs nodes are present on different hardware.
chown -f power:power "$1"/*brightness "$1"/bl_power || true
