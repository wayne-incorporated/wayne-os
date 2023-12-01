#!/bin/bash
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. /usr/share/misc/shflags || exit 1

# The USB device path detected by udev rule.
DEFINE_string 'dev' '' "device path" 'd'

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# die on error.
set -e

main() {
  control=/sys/"${FLAGS_dev}/power/control"

  if [ ! -f "$control" ]; then
    exit 1
  fi

  # disable runtime suspend
  echo on > "$control"
}

main "$@"

