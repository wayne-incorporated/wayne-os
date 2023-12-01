#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

main() {
  SCRIPT="$(realpath "$0")"
  SCRIPT_DIR="$(dirname "${SCRIPT}")"
  if ! "${SCRIPT_DIR}/../filesystem-layout.py" "${ED:-${D:-}}"; then
    die "Filesystem layout is not valid"
  fi
}
main "$@"
