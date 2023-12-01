#!/bin/sh
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Reads a given nv space index and a given size. The index is specified as the
# first input argument in a hex number, w/o "0x" prefix, followed by the read
# size in decimel as the second argument.
# Example usage: /usr/share/cros/tpm2-read-space.sh 013fff00 12

TPM2_NV_UTILS="/usr/share/cros/tpm2-nv-utils.sh"
"${TPM2_NV_UTILS}" read "$@"
