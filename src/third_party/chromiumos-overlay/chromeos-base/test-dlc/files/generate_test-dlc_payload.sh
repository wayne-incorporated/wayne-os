#!/bin/bash
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Use this script to regenerate the artifacts needed by the test-dlc.

if [ -z "${BOARD}" ]; then
  echo "BOARD variable is unset." && exit 1
else
  echo "using BOARD='${BOARD}'"
fi

set -ex

TEMP="$(mktemp -d)"
BUILD_BOARD="/build/${BOARD}"
DLC_ROOTFS_META_DIR="rootfs_meta"
DLC_PAYLOADS_DIR="payloads"
DLC_IMAGES_DIR="images"
DLC_BUILD_ROOTFS_DIR="build/rootfs/dlc"
DLC_PACKAGE="test-package"
DLC_PAYLOAD="dlcservice_test-dlc.payload"
LSB_RELEASE="etc/lsb-release"
UPDATE_ENGINE_CONF="etc/update_engine.conf"

# Creates files (truncated/hash/perm) in the files directory with given
# truncate size, name, and permissions.
generate_file() {
  local size="$1"
  local filepath="${DLC_FILES_DIR}/$2"
  local permissions="$3"
  # Read to /dev/urandom as tests are in place to check based off checksum.
  dd if=/dev/urandom of="${filepath}" bs="${size}" count=1 || die
  sha256sum "${filepath}" > "${filepath}.sum" || die
  chmod "${permissions}" "${filepath}" || die
  echo "${permissions}" > "${filepath}.perms" || die
}


mkdir -p "${DLC_PAYLOADS_DIR}" "${DLC_ROOTFS_META_DIR}" "${DLC_IMAGES_DIR}"
for N in {1..2}; do
  DLC_ID="test${N}-dlc"
  DLC_PATH="${DLC_ID}/${DLC_PACKAGE}"
  DLC_FILES_DIR="${TEMP}/${DLC_BUILD_ROOTFS_DIR}/${DLC_ID}/${DLC_PACKAGE}/root"

  mkdir -p "${DLC_FILES_DIR}/dir"  "${TEMP}"/etc
  # Don't create unreadable files as tests check based on readability.
  generate_file 10 "file1.bin" 0755
  generate_file 20 "dir/file2.bin" 0544
  generate_file 30 "dir/file3.bin" 0444

  args=(
    --install-root-dir "${TEMP}"
    --pre-allocated-blocks "5"
    --version "1.0.0"
    --id "${DLC_ID}"
    --package "${DLC_PACKAGE}"
    --name "Test${N} DLC"
    --description "Description for Test${N} DLC"
    --board "${BOARD}"
    --build-package
  )
  # For the first DLC, make it user used by the user.
  if [[ "${N}" == 1 ]]; then
    args+=( --used-by "user" )
  fi
  # For the second DLC, make preloadable.
  if [[ "${N}" == 2 ]]; then
    args+=( --preload )
  fi

  build_dlc "${args[@]}"

  cp "${BUILD_BOARD}/${LSB_RELEASE}" "${TEMP}"/etc/
  cp "${BUILD_BOARD}/${UPDATE_ENGINE_CONF}" "${TEMP}"/etc/

  build_dlc --sysroot "${TEMP}" --rootfs "${TEMP}"

  cp -r "${TEMP}/opt/google/dlc"/* "${DLC_ROOTFS_META_DIR}/"

  DLC_IMG_PATH="${TEMP}/build/rootfs/dlc/${DLC_PATH}/dlc.img"
  DLC_IMAGES_PATH="${DLC_IMAGES_DIR}/${DLC_PATH}"
  mkdir -p "${DLC_IMAGES_PATH}"
  cp "${DLC_IMG_PATH}" "${DLC_IMAGES_PATH}"

  PAYLOAD_NAME="${DLC_ID}_${DLC_PACKAGE}_${DLC_PAYLOAD}"
  cros_generate_update_payload \
      --tgt-image "${DLC_IMG_PATH}" \
      --output "${TEMP}/${PAYLOAD_NAME}"

  # Remove the AppID because it is static and nebraska won't be able to get it
  # when different boards pass different APP IDs.
  FIND_BEGIN="{\"appid\": \""
  FIND_END="_test"
  sed -i "s/${FIND_BEGIN}.*${FIND_END}/${FIND_BEGIN}${FIND_END}/" \
   "${TEMP}/${PAYLOAD_NAME}.json"

  cp "${TEMP}/${PAYLOAD_NAME}" "${TEMP}/${PAYLOAD_NAME}.json" "${DLC_PAYLOADS_DIR}/"

  sudo rm -rf "${TEMP}"
done
