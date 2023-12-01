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
  # Enable S0ix validation check in kernel
  echo "intel_idle.slp_s0_check=1" >> "$1"

  # Setup S0ix validation initial timeout for slp_s0_check
  echo "intel_idle.slp_s0_seed=5" >> "$1"

  # Don't disable the ability to run VMs.
  echo "disablevmx=off" >> "$1"

  # Enable S0ix logging using GSMI
  echo "gsmi.s0ix_logging_enable=1" >> "$1"

  # Mitigate risk from running untrusted VMs
  echo "kvm-intel.vmentry_l1d_flush=always" >> "$1"

  # Disable PSR2 by default.
  # (0=disabled, 1=enable up to PSR1, 2=enable up to PSR2)
  # Temporary WA until b:203856237 is root caused and fixed
  echo "i915.enable_psr=1" >> "$1"
}
