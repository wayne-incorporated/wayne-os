#!/bin/bash

# Copyright 2020 The ChromiumOS Authors
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

  # Enable S0ix logging using GSMI
  echo "gsmi.s0ix_logging_enable=1" >> "$1"

  # Check for S0ix failures and show warnings on failures
  echo "intel_pmc_core.warn_on_s0ix_failures=1" >> "$1"

  # Enable Guc and Huc loading. When enable_guc is set to 3,
  # it supports guc/huc loading and guc submission.
  echo "i915.enable_guc=3" >> "$1"

  # Enable power-saving display c states. Setting the value of 4
  # enables up to DC6 with DC3C0.
  echo "i915.enable_dc=4" >> "$1"

  # Disable xDomain protocol on the thunderbolt driver
  echo "xdomain=0" >> "$1"

  # The 5G driver requires a lot of swiotlb buffers (b/201020414)
  # So increase the swiotlb slots from default 32768 (64MB) to 65536 (128MB)
  echo "swiotlb=65536" >> "$1"

  # Ensure internal devices are also in their own DMA domain, enable IOMMU PT.
  echo "intel_iommu=on iommu=pt" >> "$1"

  # Disable Nouveau.
  echo "nouveau_modeset=0" >> "$1"

  # Disable PSR2 by default.
  # (0=disabled, 1=enable up to PSR1, 2=enable up to PSR2)
  # Temporary WA until b:216826833 is root caused and fixed
  #                and b:243060986 is root caused and fixed:
  #                   Disable PSR2 to make panel work.
  #                   Manufacturer: BOE (on some Redrix SKUs)
  #                   Model: 2678
  #                   Made in week 25 of 2021
  echo "i915.enable_psr=1" >> "$1"

  #disable UAS only for Framework storage card.
  #The expansion card supports UAS disappeared in
  #the Files app when the system woke up from s0ix.
  #Add usb-storage.quirks=13fe:6500:u to disable UAS
  echo "usb-storage.quirks=13fe:6500:u" >> "$1"
}
