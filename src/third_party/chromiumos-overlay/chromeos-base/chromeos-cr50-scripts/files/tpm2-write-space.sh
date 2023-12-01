#!/bin/sh
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Writes given data in hex format to a given index.
# Example usage: /usr/share/cros/tpm2-write-space.sh 013fff00 ff0123

TPM2_NV_UTILS="/usr/share/cros/tpm2-nv-utils.sh"
"${TPM2_NV_UTILS}" write "$@"
