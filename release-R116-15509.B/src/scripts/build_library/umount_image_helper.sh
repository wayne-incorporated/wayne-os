#!/bin/bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

SCRIPT_ROOT=$(readlink -f -- "$(dirname -- "$0")")

usage() {
  cat <<EOF
Usage: $0 [-h|--help]

Unmount the disk image in ${SCRIPT_ROOT} and delete dir_* paths.
EOF
}

main() {
  if [[ $# -ne 0 ]]; then
    usage
    exit 1
  fi

  cd "${SCRIPT_ROOT}" || exit 1

  # See if any paths exist to avoid errors with missing paths.
  set -- dir_[0-9]*
  if [[ $# -gt 1 || "$1" != "dir_[0-9]*" ]]; then
    find dir_[0-9]* -maxdepth 0 -type l -delete
  fi

  # See if any paths exist to avoid errors with missing paths.
  set -- dir_[0-9]*
  if [[ $# -gt 1 || "$1" != "dir_[0-9]*" ]]; then
    sudo umount -r dir_[0-9]*
    rmdir dir_[0-9]*
  fi
}

main "$@"
