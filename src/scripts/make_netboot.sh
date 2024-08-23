#!/bin/bash

# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# make_netboot.sh --board=[board]
#
# This script builds a kernel image bundle with the factory install shim
# included as initramfs. Generated image, along with the netboot firmware
# are placed in a "netboot" subfolder.

SCRIPT_ROOT="$(dirname "$(readlink -f "$0")")"
# shellcheck source=build_library/build_common.sh
. "${SCRIPT_ROOT}/build_library/build_common.sh" || exit 1

# Script must be run inside the chroot.
restart_in_chroot_if_needed "$@"

# shellcheck disable=SC2154
DEFINE_string board "${DEFAULT_BOARD}" \
  "The board to build an image for."
DEFINE_string image_dir "" "Path to the folder to store netboot images."

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# shellcheck disable=SC2154
# shellcheck source=build_library/board_options.sh
. "${BUILD_LIBRARY_DIR}/board_options.sh" || exit 1

switch_to_strict_mode
# build_packages artifact output.
SYSROOT="/build/${FLAGS_board}"
# build_image artifact output.

if [ -n "${FLAGS_image_dir}" ]; then
  cd "${FLAGS_image_dir}" || die
else
  # shellcheck disable=SC2154
  cd "${CHROOT_TRUNK_DIR}/src/build/images/${FLAGS_board}/latest" || die
fi

# Generate staging dir for netboot files.
info_run sudo rm -rf netboot
info_run mkdir -p netboot

# Get netboot firmware.
FIRMWARE_PATTERN="firmware/image*.net.bin"
# shellcheck disable=SC2206
FIRMWARE_PATHS=("${SYSROOT}"/${FIRMWARE_PATTERN})
# When there is no netboot firmware found, filename expansion fails and the
# array still contains the original pattern string, so we need to check if the
# first file in the array actually exists to know if we find any firmware.
if [ -e "${FIRMWARE_PATHS[0]}" ]; then
  info "Copying netboot firmware"
  for firmware_path in "${FIRMWARE_PATHS[@]}"; do
    info_run cp "${firmware_path}" netboot/
  done
else
  warn "Skipping netboot firmware: ${SYSROOT}/${FIRMWARE_PATTERN} not present?"
fi

# Create temporary emerge root
temp_build_path="$(mktemp -d bk_XXXXXXXX)" || die "Failed to create tempdir."

# Build initramfs network boot image
info "Building kernel"
export USE="fbconsole vtconsole factory_netboot_ramfs i2cdev vfat"
export EMERGE_BOARD_CMD="emerge-${FLAGS_board}"
emerge_custom_kernel "${temp_build_path}"

# Place kernel image under 'netboot'
KERNEL_PATH="/boot/vmlinuz"
if [ -f "${temp_build_path}${KERNEL_PATH}" ]; then
  info "Generating netboot kernel ${KERNEL_PATH}"
  info_run cp "${temp_build_path}${KERNEL_PATH}" netboot/
else
  warn "No ${KERNEL_PATH} found in your board."
fi

info_run sudo rm -rf "${temp_build_path}"
