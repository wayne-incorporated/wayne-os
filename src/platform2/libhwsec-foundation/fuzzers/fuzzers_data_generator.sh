#!/usr/bin/env bash
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Generates constant data files for the cryptohome fuzzers.
# Execute it if you need to re-generate the data files, which are normally
# committed to the source tree.

set -e

cd "$(dirname "$0")"

generate_key()
{
  local KEY_SIZE_BITS=$1
  local KEY_INDEX=$2

  local OUTPUT_FILE_PATH="testdata/fuzzer_key_rsa_${KEY_SIZE_BITS}_${KEY_INDEX}"
  openssl genrsa -out "${OUTPUT_FILE_PATH}" "${KEY_SIZE_BITS}"
}

for KEY_SIZE_BITS in 512 1024 2048 4096; do
  generate_key "${KEY_SIZE_BITS}" "1"
generate_key "${KEY_SIZE_BITS}" "2"
done
