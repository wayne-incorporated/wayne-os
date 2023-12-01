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

  # Enable GuC loading
  echo "i915.enable_guc=3" >> "$1"

  # Check for S0ix failures and show warnings on failures
  echo "intel_pmc_core.warn_on_s0ix_failures=1" >> "$1"

  # Ensure internal devices are also in their own DMA domain
  echo "intel_iommu=on" >> "$1"

  # The 5G driver requires a lot of swiotlb buffers (b/201020414)
  # So increase the swiotlb slots from default 32768 (64MB) to 65536 (128MB)
  echo "swiotlb=65536" >> "$1"
}
