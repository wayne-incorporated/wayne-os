#!/bin/sh
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

OV13858_EEPROM="/sys/bus/i2c/devices/i2c-INT3499:00/eeprom"
OV13858_VENDOR_ID_FILE="$(cat /sys/bus/i2c/devices/i2c-OVTID858:00/vendor_id)"
OV13858_LITEON_VENDOR_ID=21

chgrp arc-camera "${OV13858_EEPROM}"
chmod 440 "${OV13858_EEPROM}"

# Module part number are appended to distinguish AIQB files of different vendor.
if [ "${OV13858_VENDOR_ID_FILE}" = "${OV13858_LITEON_VENDOR_ID}" ]; then
  echo "Link to Liteon AIQB"
  ln -sf /etc/camera/ipu3/ov13858_7BAD03T2.aiqb \
      /etc/camera/ipu3/00ov13858.aiqb
else
  echo "Link to Quanta AIQB"
  ln -sf /etc/camera/ipu3/ov13858_TFC13MYHCE.aiqb \
        /etc/camera/ipu3/00ov13858.aiqb
fi
