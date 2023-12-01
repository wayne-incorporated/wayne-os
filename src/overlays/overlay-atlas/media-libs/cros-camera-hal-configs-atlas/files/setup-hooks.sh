#!/bin/sh
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

IMX208_EEPROM="/sys/bus/i2c/devices/i2c-INT3499:00/eeprom"
if [ -e "${IMX208_EEPROM}" ]; then
  chmod 440 "${IMX208_EEPROM}"
  chgrp arc-camera "${IMX208_EEPROM}"
else
  echo "no imx208 eeprom"
fi
