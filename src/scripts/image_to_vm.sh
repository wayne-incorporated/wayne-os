#!/bin/bash

# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to convert the output of build_image.sh to a QEMU image.

# Helper scripts should be run from the same location as this script.
SCRIPT_ROOT=$(dirname "$(readlink -f "$0")")
. "${SCRIPT_ROOT}/common.sh" || exit 1
. "${SCRIPT_ROOT}/build_library/ext2_sb_util.sh" || exit 1

# Need to be inside the chroot to load chromeos-common.sh
assert_inside_chroot

# Default values for creating VM's.
DEFAULT_QEMU_IMAGE="chromiumos_qemu_image.bin"

# Flags
DEFINE_string adjust_part "" \
  "Adjustments to apply to the partition table"
DEFINE_string board "${DEFAULT_BOARD}" \
  "Board for which the image was built"
DEFINE_string from "" \
  "Directory containing rootfs.image and mbr.image"
DEFINE_string disk_layout "2gb-rootfs-updatable" \
  "The disk layout type to use for this image."
DEFINE_boolean test_image "${FLAGS_FALSE}" \
  "Use ${CHROMEOS_TEST_IMAGE_NAME} instead of ${CHROMEOS_IMAGE_NAME}."
DEFINE_string to "" \
  "Destination folder for VM output file(s)"

# Parse command line
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Die on any errors.
switch_to_strict_mode

# Get the size of a regular file or a block device.
#
# $1 - The regular file or block device to get the size of.
bd_safe_size() {
  local file="$1"
  if [[ -b "${file}" ]]; then
    sudo blockdev --getsize64 "${file}"
  else
    stat -c%s "${file}"
  fi
}

TEMP_DIR=$(mktemp -d)
TEMP_MNT=""
TEMP_ESP_MNT=""
SRC_DEV=""
DST_DEV=""
cleanup() {
  if [[ -n "${TEMP_MNT}" ]]; then
    safe_umount "${TEMP_MNT}" || true
    rmdir "${TEMP_MNT}" || true
  fi
  if [[ -n "${TEMP_ESP_MNT}" ]]; then
    safe_umount "${TEMP_ESP_MNT}" || true
    rmdir "${TEMP_ESP_MNT}" || true
  fi

  if [[ -n "${SRC_DEV}" ]]; then
    loopback_detach "${SRC_DEV}" || true
  fi
  if [[ -n "${DST_DEV}" ]]; then
    loopback_detach "${DST_DEV}" || true
  fi
  rm -rf "${TEMP_DIR}"
}
trap 'ret=$?; cleanup; die_err_trap ${ret}' INT TERM EXIT

# Default to the most recent image
if [ -z "${FLAGS_from}" ] ; then
  FLAGS_from="${IMAGES_DIR}/${FLAGS_board}/latest"
fi
if [ -z "${FLAGS_to}" ] ; then
  FLAGS_to="${FLAGS_from}"
fi

# Convert args to full paths.  Use echo here on the unquoted value to process all
# shell level expansions like ~ and *.
if ! resolved=$(readlink -f "$(echo ${FLAGS_from})"); then
  die_notrace "image_to_vm: processing --from failed." \
    "Verify the path exists: ${FLAGS_from}" \
    "  cwd: ${PWD}"
fi
FLAGS_from=${resolved}
if ! resolved=$(readlink -f "$(echo ${FLAGS_to})"); then
  die_notrace "image_to_vm: Processing --to failed." \
    "Verify the path exists: ${FLAGS_to}" \
    "  cwd: ${PWD}"
fi
FLAGS_to=${resolved}

if [ ${FLAGS_test_image} -eq ${FLAGS_TRUE} ]; then
  SRC_IMAGE="${FLAGS_from}/${CHROMEOS_TEST_IMAGE_NAME}"
else
  # Use the standard image
  SRC_IMAGE="${FLAGS_from}/${CHROMEOS_IMAGE_NAME}"
fi
if [[ ! -e ${SRC_IMAGE} ]]; then
  die_notrace "image_to_vm: src image does not exist: ${SRC_IMAGE}" \
    "Please verify you have selected the right input." \
    "Note: only dev/test/factory images can be used as inputs."
fi

if [[ -z "${FLAGS_board}" ]] && [[ -n "${FLAGS_from}" ]]; then
  # The user may not know the board of in the input image, so infer it for them.
  # TODO(pprabhu): This will fail if the user's chroot has a default_board set
  # which is different from the image provided, because FLAGS_board will use
  # that. Fix this project-wide by respecting the --board flag when provided,
  # but preferring the board inferred from FLAGS_from over the default,
  # everywhere.
  FLAGS_board="$(
    . "${BUILD_LIBRARY_DIR}/mount_gpt_util.sh"
    get_board_from_image "${SRC_IMAGE}"
  )"
fi

if [[ ! -d "/build/${FLAGS_board}" ]]; then
  # Using board options and overrides requires that the board sysroot be setup
  # (in order to read kernel and disk-image options).
  # OTOH, we don't actually need to build any packages / update the host
  # sysroot.
  setup_board --quiet --board="${FLAGS_board}" \
    --skip-toolchain-update --skip-chroot-upgrade --skip-board-pkg-init
fi
. "${BUILD_LIBRARY_DIR}/board_options.sh" || exit 1
. "${SCRIPT_ROOT}/build_library/disk_layout_util.sh" || exit 1

# Memory units are in MBs
TEMP_IMG="$(dirname "${SRC_IMAGE}")/vm_temp_image.bin"

# Split apart the partitions and make some new ones
SRC_DEV=$(loopback_partscan "${SRC_IMAGE}")

# Fix the kernel command line
SRC_STATE="${SRC_DEV}"p1
SRC_ROOTFS="${SRC_DEV}"p3
SRC_KERN="${SRC_DEV}"p4
SRC_OEM="${SRC_DEV}"p8
SRC_ESP="${SRC_DEV}"p12
STATEFUL_SIZE_BYTES=$(get_filesystem_size "${FLAGS_disk_layout}" 1)
STATEFUL_SIZE_MEGABYTES=$(( STATEFUL_SIZE_BYTES / 1024 / 1024 ))
original_image_size=$(bd_safe_size "${SRC_STATE}")
if [ "${original_image_size}" -gt "${STATEFUL_SIZE_BYTES}" ]; then
  if [ $(( original_image_size - STATEFUL_SIZE_BYTES )) -lt \
      $(( 10 * 1024 * 1024 )) ]; then
    # cgpt.py adds makeup padding to paritions to counteract alignment losses.
    # Each partition gets expanded by an additional `fs_block_size` bytes, and
    # in the case where `fs_align` is defined, rootfs and data partitions get
    # expanded by `fs_align` bytes:
    #
    # https://chromium.googlesource.com/chromiumos/platform/crosutils/+/HEAD/build_library/cgpt.py#554
    #
    # The original legacy_disk_layout.json does not specify `fs_align`, which
    # results in an image size that is only slightly larger than is specified
    # in the disk layout. disk_layout_v2.json sets `fs_align` to 2MiB, which
    # results in a significantly larger delta. Therefore:
    #
    # max_delta = fs_align * (# in use data and rootfs partitions + 1)
    #
    # With that in mind, set the maximum delta to 10MiB for now: this should be
    # sufficient to support both disk_layout_v2.json and disk_layout_v3.json
    # based layouts.
    TEMP_STATE="${SRC_STATE}"
  else
    die "Cannot resize stateful image to smaller than original. Exiting."
  fi
else
  echo "Resizing stateful partition to ${STATEFUL_SIZE_MEGABYTES}MB"
  # Extend the original file size to the new size.
  TEMP_STATE="${TEMP_DIR}"/stateful
  # Create TEMP_STATE as a regular user so a regular user can delete it.
  sudo dd if="${SRC_STATE}" bs=16M status=none > "${TEMP_STATE}"
  sudo e2fsck -pf "${TEMP_STATE}"
  sudo resize2fs "${TEMP_STATE}" ${STATEFUL_SIZE_MEGABYTES}M
fi
TEMP_PMBR="${TEMP_DIR}"/pmbr
dd if="${SRC_IMAGE}" of="${TEMP_PMBR}" bs=512 count=1

# Set up a new partition table.
PARTITION_SCRIPT_PATH=$(mktemp)
write_partition_script "${FLAGS_disk_layout}" "${PARTITION_SCRIPT_PATH}"
. "${PARTITION_SCRIPT_PATH}"
write_partition_table "${TEMP_IMG}" "${TEMP_PMBR}"
rm "${PARTITION_SCRIPT_PATH}"

DST_DEV=$(loopback_partscan "${TEMP_IMG}")
DST_STATE="${DST_DEV}"p1
DST_ROOTFS="${DST_DEV}"p3
DST_KERN="${DST_DEV}"p4
DST_OEM="${DST_DEV}"p8
DST_ESP="${DST_DEV}"p12

# Copy into the partition parts of the file.
# When copying to (or from) a non-regular file, cp ignores --sparse. Since we
# have created a collection of empty partitions for the new image above, we can
# use 'dd conv=sparse' to both speed up the copy, and (apparently) avoid
# b/135292499.  See also crbug.com/957712.  This only works because we know that
# the destination partition is all zeros.
sudo dd if="${SRC_ROOTFS}" of="${DST_ROOTFS}" conv=sparse bs=2M
sudo dd if="${TEMP_STATE}" of="${DST_STATE}"  conv=sparse bs=2M
sudo dd if="${SRC_ESP}"    of="${DST_ESP}"    conv=sparse bs=2M
sudo dd if="${SRC_OEM}"    of="${DST_OEM}"    conv=sparse bs=2M
sync

TEMP_MNT=$(mktemp -d)
TEMP_ESP_MNT=$(mktemp -d)
mkdir -p "${TEMP_MNT}"
enable_rw_mount "${DST_ROOTFS}"
sudo mount "${DST_ROOTFS}" "${TEMP_MNT}"
mkdir -p "${TEMP_ESP_MNT}"
sudo mount "${DST_ESP}" "${TEMP_ESP_MNT}"

# Unmount everything prior to building a final image
trap 'die_err_trap' INT TERM EXIT
cleanup

# Make the built-image bootable.
# NOTE: The TEMP_IMG must live in the same image dir as the original image
#       to operate automatically below.
${SCRIPTS_DIR}/bin/cros_make_image_bootable $(dirname "${TEMP_IMG}") \
                                            $(basename "${TEMP_IMG}") \
                                            --force_developer_mode

IMAGE_DEV=""
detach_loopback() {
  if [ -n "${IMAGE_DEV}" ]; then
    loopback_detach "${IMAGE_DEV}"
  fi
}
trap 'ret=$?; detach_loopback; die_err_trap ${ret}' INT TERM EXIT

# cros_make_image_bootable made the kernel in slot A recovery signed. We want
# it to be normally signed like the one in slot B, so copy B into A.
# Because cros_make_image_bootable overwrote p2 above, we cannot do a sparse
# copy.
IMAGE_DEV=$(loopback_partscan "${TEMP_IMG}")
sudo dd if=${IMAGE_DEV}p4 of=${IMAGE_DEV}p2 bs=2M
sync

trap 'die_err_trap' INT TERM EXIT
switch_to_strict_mode
loopback_detach "${IMAGE_DEV}"

echo Creating final image
mv "${TEMP_IMG}" "${FLAGS_to}/${DEFAULT_QEMU_IMAGE}"

rm -rf "${TEMP_IMG}"

echo "Created image at ${FLAGS_to}"

echo "You can start the image with:"
echo "cros_vm --start --board ${FLAGS_board} \
--image-path ${FLAGS_to}/${DEFAULT_QEMU_IMAGE}"
