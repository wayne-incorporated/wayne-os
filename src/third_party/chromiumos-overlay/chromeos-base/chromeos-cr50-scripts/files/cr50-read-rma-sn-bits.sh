#!/bin/sh
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script reads S/N vNVRAM data from cr50 as a part of the factory process.
# The data is printed as vvvvvv:rr:ss..ss, where
#   vvvvvv is the hex representation of the 3 version bytes,
#   rr is the hex representation of the RMA status byte,
#   ss..SS is the hex representation of SN Bits (12 bytes).

PLATFORM_INDEX=false
TPM_READSPACE="/usr/share/cros/tpm2-read-space.sh"

if ! sn_bits="$(${TPM_READSPACE} 013fff01 16)"; then
  >&2 echo "Failed to read SN Bits space"
  exit 1
fi

standalone_rma_bytes=""
if [ "${PLATFORM_INDEX}" = true ]; then
  if ! standalone_rma_bytes="$(${TPM_READSPACE} 013fff04 4)"; then
    >&2 echo "Failed to read RMA Bytes space"
    exit 1
  fi
fi

sn_data_version="$(echo "${sn_bits}" | cut -b 1-6)"
rma_status="$(echo "${sn_bits}" | cut -b 7-8)"
sn_bits="$(echo "${sn_bits}" | cut -b 9-)"
# For non-platform index case, ${standalone_rma_bytes} is empty; use `xargs` to trim the space at tail.
echo "${sn_data_version}:${rma_status}:${sn_bits} ${standalone_rma_bytes}" | xargs
