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
  # Might be helpful to preserve ramoops in extreme circumstances
  echo "ramoops.ecc=1" >> "$1"

  # Enable S0ix logging using GSMI
  echo "gsmi.s0ix_logging_enable=1" >> "$1"

  # Check for S0ix failures and show warnings on failures
  echo "intel_pmc_core.warn_on_s0ix_failures=1" >> "$1"

  # enable IOMMU
  echo "intel_iommu=on iommu=pt" >> "$1"

  echo "nouveau_modeset=0" >> "$1"

  # enable USB serial console for debugging
  echo "earlyprintk=serial,ttyUSB0,115200n8" >> "$1"
  echo "console=ttyUSB0,115200,keep" >> "$1"

  # get sound working
  echo "snd-intel-dspcfg.dsp_driver=1" >> "$1"
}
