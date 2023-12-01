#!/bin/bash

# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# All kernel command line changes must update the security base lines in
# the signer.  It rejects any settings it does not recognize and breaks the
# build.  So any modify_kernel_command_line() function change here needs to be
# reflected in ensure_secure_kernelparams.config.

# See crrev.com/i/216896 as an example.

modify_kernel_command_line() {
 {
  # disablevmx=off is set by baseboard-fizz, but since build_kernel_image.sh
  # does not support inheritance, this board-specific file overrides its
  # definition of modify_kernel_command_line (https://crbug.com/868003),
  # so include its contents here.
  echo "disablevmx=off"

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

  # Enable l1d_flush for untrusted VM security
  echo "kvm-intel.vmentry_l1d_flush=always" >> "$1"
 } >> "$1"
}
