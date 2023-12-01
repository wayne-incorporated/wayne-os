#!/bin/bash

# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# All kernel command line changes must update the security base lines in
# the signer.  It rejects any settings it does not recognize and breaks the
# build.  So any modify_kernel_command_line() function change here needs to be
# reflected in ensure_secure_kernelparams.config.

# See crrev.com/i/216896 as an example.

modify_kernel_command_line() {
    {
        echo "disablevmx=off";
        echo "kvm-intel.vmentry_l1d_flush=always";
        echo "i915.enable_dpcd_backlight=1";
        echo "i915.enable_dbc=1";
        echo "i915.enable_guc_loading=1";
        echo "i915.enable_guc_submission=0";
    } >> "$1"
}
