#!/bin/sh
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

DW9807_EEPROM="/sys/bus/i2c/devices/i2c-INT3499:00/eeprom"

chgrp arc-camera "${DW9807_EEPROM}"
chmod 440 "${DW9807_EEPROM}"
