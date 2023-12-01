#!/bin/bash

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# All kernel command line changes must update the security base lines in
# the signer.  It rejects any settings it does not recognize and breaks the
# build.  So any modify_kernel_command_line() function change here needs to be
# reflected in ensure_secure_kernelparams.config.

# See crrev.com/i/216896 as an example.

modify_kernel_command_line() {
  {
    # Inherited parameters from parent overlay: baseboard-fizz.
    # Context: build_kernel_image.sh does not support inheritance so this
    # board-specific file overrides modify_kernel_command_line definition
    # in parents overlays. Hence we need to include its content here.

    echo "disablevmx=off"
    # Enable l1d_flush for untrusted VM security
    echo "kvm-intel.vmentry_l1d_flush=always"

    # fizz-labstation specific parameters start here.

    # Disables GPU power management due to the problems with the power
    # management features found in low-power Intel chips, which result
    # to random labstation crash/stuck in booting loop due to kernel panic.
    # See b/198650616#comment23.
    echo "i915.enable_dc=0"
  } >> "$1"
}
