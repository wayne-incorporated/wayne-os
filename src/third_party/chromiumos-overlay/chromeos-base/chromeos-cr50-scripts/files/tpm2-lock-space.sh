#!/bin/sh
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Write-locks a given nv space index. The index is specified as the first input
# argument in a hex number, w/o "0x" prefix.
# Example usage: /usr/share/cros/tpm2-lock-space.sh 013fff00

TPM2_NV_UTILS="/usr/share/cros/tpm2-nv-utils.sh"
"${TPM2_NV_UTILS}" writelock "$@"
