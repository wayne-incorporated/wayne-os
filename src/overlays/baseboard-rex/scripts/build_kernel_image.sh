#!/bin/bash

# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# All kernel command line changes must update the security base lines in
# the signer.  It rejects any settings it does not recognize and breaks the
# build.  So any modify_kernel_command_line() function change here needs to be
# reflected in ensure_secure_kernelparams.config.

# See crrev.com/i/216896 as an example.

modify_kernel_command_line() {
  # Avoid a cosmetic TPM error (Work around for b/113527055)
  sed -i -e '/tpm_tis.force/d' "$1"
  {
    echo "tpm_tis.force=0"

    # Might be helpful to preserve ramoops in extreme circumstances
    echo "ramoops.ecc=1"

    # Check for S0ix failures and show warnings on failures
    echo "intel_pmc_core.warn_on_s0ix_failures=1"

    # Enable Guc and Huc loading. When enable_guc is set to 3,
    # it supports guc/huc loading and guc submission.
    echo "i915.enable_guc=3"

    # Enable power-saving display c states. Setting the value of 4
    # enables up to DC6 with DC3C0.
    echo "i915.enable_dc=4"

    # Disable xDomain protocol on the thunderbolt driver
    echo "xdomain=0"

    # Disable PSR2 by default.
    echo "i915.enable_psr=1"

    # Enable Intel's iommu driver.
    # There are a few known issues with MTL ES0/ES1
    # (see b/278761218#comment6 for more info),
    # so instead of using "intel_iommu=on" we use the arguments
    # below as a workaround. This will be removed in
    # August 2023 (when everyone will be using ES2).
    echo "intel_iommu=on,sm_on iommu=pt"

    # Disabling DPT (for context see b:270540659)
    echo "i915.enable_dpt=0"

    # Display kernel debug messages on the UART
    echo "earlyprintk=serial,ttyS0,115200n8 console=ttyS0,115200n8,keep"

    # The 5G driver requires a lot of swiotlb buffers (b/284465894)
    # So increase the swiotlb slots from default 32768 (64MB) to 65536 (128MB)
    echo "swiotlb=65536"
  } >> "$1"
}
