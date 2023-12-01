#!/bin/sh
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Reads board id space and format it as "XXXXXXXX:XXXXXXXX:XXXXXXXX" in hex.
# Note that for compatibility with gsctool, the endian of respective 4 bytes are
# reversed.

TPM_READSPACE="/usr/share/cros/tpm2-read-space.sh"

if ! board_id_data="$("${TPM_READSPACE}" 013fff00 12)"; then
  >&2 echo "Failed to read board id space"
  exit 1
fi

reverse_endian() {
  local v=$1
  echo "${v}" | tac -rs .. | tr -d '\n'
}

# Extract and print RMA and SNbits data.
board_id_part1="$(echo "${board_id_data}" | cut -b 1-8)"
board_id_part2="$(echo "${board_id_data}" | cut -b 9-16)"
flags="$(echo "${board_id_data}" | cut -b 17-24)"

board_id_part1="$(reverse_endian "${board_id_part1}")"
board_id_part2="$(reverse_endian "${board_id_part2}")"
flags="$(reverse_endian "${flags}")"

echo "${board_id_part1}:${board_id_part2}:${flags}"
