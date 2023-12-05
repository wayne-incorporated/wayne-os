#!/bin/bash
# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

BUILD_LIBRARY_DIR=$(dirname $0)
# shellcheck source=filesystem_util.sh
. "${BUILD_LIBRARY_DIR}/filesystem_util.sh" || exit 1

set -e -u

# Make die() non-fatal for testing.
exit() {
  echo exit "$@"
}

output_test() {
  local expected_output="$1"
  echo "Testing ${*:2}"
  local actual_output=$("${@:2}")
  if [[ "${expected_output}" != "${actual_output}" ]]; then
    set -x
    actual_output=$("${@:2}")
    set +x
    echo "  Expected: ${expected_output}"
    echo "  Actual:   ${actual_output}"
    false
  fi
}

# key= is parsed as the empty string value
output_test "" fs_parse_option "loop=,ro,offset=1234" "loop" 42

# "key" (without the = after it) is parsed as the empty value as well.
output_test "" fs_parse_option "loop=,ro,offset=1234" "ro" 42

# Make sure "keystuff" is not confused with just "key"
output_test 42 fs_parse_option "loop=,rostuff,offset=1234" "ro" 42

output_test 42 fs_parse_option "loop=,ro,offset=1234" "laap" 42
# offset= interacts with dirty pages in the file in a very poor manner.
# See crbug.com/954188
output_test 'exit 1' fs_parse_option "loop=,ro,offset=1234" "offset" ""

output_test 42 fs_parse_option "loop=,ro,offset=1234" "laap" 42

echo "All tests passed."
exit 0
