#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -u -e

CONFIGFS_IMAGE="/usr/share/chromeos-config/configfs.img"
SQUASHFS_BASE="/run/chromeos-config/private"

CROSID_ARGS=()

print_usage () {
  cat <<EOF >&2
Usage: $0 [OPTIONS...] PATH PROPERTY

Optional arguments:
  --sku-id SKU              Override the SKU id from firmware.
  --custom-label-tag VALUE  Override the custom label tag from VPD.
  --help                    Show this help message and exit.

Positional arguments:
  PATH                    The path to get from config.
  PROPERTY                The property to get from config.
EOF
}

if [[ "${#@}" -eq 0 ]]; then
  print_usage
  exit 1
fi

while [[ "${1:0:1}" != "/" ]]; do
  case "$1" in
    --sku-id )
      CROSID_ARGS+=( --sku-id "$2" )
      shift
      ;;
    --custom-label-tag )
      CROSID_ARGS+=( --custom-label-tag "$2" )
      shift
      ;;
    --help )
      print_usage
      exit 0
      ;;
    * )
      print_usage
      echo >&2
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "${#@}" -ne 2 ]]; then
  print_usage
  exit 1
fi

PATH_NAME="$1"
PROPERTY_NAME="$2"
CONFIG_INDEX="$(crosid -f CONFIG_INDEX "${CROSID_ARGS[@]}")"

on_exit_unmount () {
  umount "${SQUASHFS_BASE}"
  rmdir "${SQUASHFS_BASE}"
}

if ! [[ -d "${SQUASHFS_BASE}" ]]; then
  SQUASHFS_BASE="$(mktemp -d)"
  mount -oro "${CONFIGFS_IMAGE}" "${SQUASHFS_BASE}"
  trap on_exit_unmount EXIT
fi

cat "${SQUASHFS_BASE}/v1/chromeos/configs/${CONFIG_INDEX}/${PATH_NAME}/${PROPERTY_NAME}"
