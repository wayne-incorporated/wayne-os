#!/bin/bash

# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

modify_kernel_command_line() {
 {
  # Disable USB 3.0 LPM for Huddly Go
  quirks="2bd9:0011:k,"
  # Disable USB 3.0 LPM for Huddly IQ in Boxfish mode
  quirks+="2bd9:0021:k,"
  # Disable USB 3.0 LPM for Huddly IQ in Clownfish mode
  quirks+="2bd9:0031:k,"
  # Disable USB 3.0 LPM for Logitech Tap Display (Displaylink)
  quirks+="17e9:ff13:k,"
  # Disable USB 3.0 LPM for Logitech HDMI Capture
  quirks+="046d:0876:k"
  # Aggregate and export
  echo "usbcore.quirks=${quirks}"

  # Force tpm_tis
  echo "tpm_tis.force=1"
  echo "tpm_tis.interrupts=0"
 } >> "$1"
}
