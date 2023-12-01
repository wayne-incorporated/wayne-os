#!/bin/bash
# Copyright 2021 The ChromiumOS Authors
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
  local enabled_device=(dooly)
  local device=''

  device="\b$(cros_config / name)\b"
  control=/sys/"${FLAGS_dev}/power/control"

  if [[ ! "${enabled_device[*]}" =~ ${device} ]]; then
    exit 0
  fi

  if [ ! -f "${control}" ]; then
    exit 1
  fi

  # disable runtime suspend
  echo on > "${control}"
}

main "$@"
