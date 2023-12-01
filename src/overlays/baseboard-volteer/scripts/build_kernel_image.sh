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

  # Avoid a cosmetic TPM error (Work around for b/113527055)
  sed -i -e '/tpm_tis.force/d' "$1"
  echo "tpm_tis.force=0" >> "$1"

  # Check for S0ix failures and show warnings on failures
  echo "intel_pmc_core.warn_on_s0ix_failures=1" >> "$1"

  # Load GuC and HuC firmware
  echo "i915.enable_guc=2" >> "$1"

  # Disable xDomain protocol on the thunderbolt driver
  echo "xdomain=0" >> "$1"

  # Ensure internal devices are also in their own DMA domain,
  # isolated from other devices, just like external devices.
  echo "intel_iommu=on" >> "$1"

  # Disable PSR2 by default.
  # (0=disabled, 1=enable up to PSR1, 2=enable up to PSR2)
  echo "i915.enable_psr=1" >> "$1"
}
