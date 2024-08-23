#!/bin/bash

# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script modifies a base image to act as a recovery installer.
# If no kernel image is supplied, it will build a devkeys signed recovery
# kernel.  Alternatively, a signed recovery kernel can be used to
# create a Chromium OS recovery image.

SCRIPT_ROOT="$(dirname "$(readlink -f "$0")")"
# shellcheck source=/build_library/build_common.sh
. "${SCRIPT_ROOT}/build_library/build_common.sh" || exit 1
# shellcheck source=build_library/disk_layout_util.sh
. "${SCRIPT_ROOT}/build_library/disk_layout_util.sh" || exit 1

# Default recovery kernel name.
RECOVERY_KERNEL_NAME=recovery_vmlinuz.image

# shellcheck disable=SC2154
DEFINE_string board "${DEFAULT_BOARD}" \
  "board for which the image was built" \
  b
DEFINE_integer statefulfs_sectors 4096 \
  "number of free sectors in stateful filesystem when minimizing"
DEFINE_string kernel_image "" \
  "path to a pre-built recovery kernel"
DEFINE_string kernel_outfile "" \
  "emit recovery kernel to path/file (${RECOVERY_KERNEL_NAME} if empty)"
# shellcheck disable=SC2154
DEFINE_string image "" \
  "source image to use (${CHROMEOS_IMAGE_NAME} if empty)"
# shellcheck disable=SC2154
DEFINE_string to "" \
  "emit recovery image to path/file (${CHROMEOS_RECOVERY_IMAGE_NAME} if empty)"
DEFINE_boolean kernel_image_only "${FLAGS_FALSE}" \
  "only emit recovery kernel"
DEFINE_boolean sync_keys "${FLAGS_TRUE}" \
  "update install kernel with the vblock from stateful"
DEFINE_boolean minimize_image "${FLAGS_TRUE}" \
  "create a minimized recovery image from source image"
DEFINE_boolean modify_in_place "${FLAGS_FALSE}" \
  "modify source image in place"
# shellcheck disable=SC2034
DEFINE_integer jobs -1 \
  "how many packages to build in parallel at maximum" \
  j
# shellcheck disable=SC2034
DEFINE_string build_root "/build" \
  "root location for board sysroots"
DEFINE_string keys_dir "${VBOOT_DEVKEYS_DIR}" \
  "directory containing the signing keys"
DEFINE_boolean verbose "${FLAGS_FALSE}" \
  "log all commands to stdout" v
DEFINE_boolean decrypt_stateful "${FLAGS_FALSE}" \
  "request a decryption of the stateful partition (implies --nominimize_image)"
DEFINE_string enable_serial "" \
  "Enable serial output (same as build_kernel_image.sh). Example: ttyS0"

# Parse command line
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Only now can we die on error.  shflags functions leak non-zero error codes,
# so will die prematurely if 'switch_to_strict_mode' is specified before now.
switch_to_strict_mode

if [ "${FLAGS_verbose}" -eq "${FLAGS_TRUE}" ]; then
  # Make debugging with -v easy.
  set -x
fi

# We need space for copying decrypted files to the recovery image, so force
# --nominimize_image when using --decrypt_stateful.
if [ "${FLAGS_decrypt_stateful}" -eq "${FLAGS_TRUE}" ]; then
  FLAGS_minimize_image="${FLAGS_FALSE}"
fi

# Load board options.
# shellcheck source=build_library/board_options.sh
# shellcheck disable=SC2154
. "${BUILD_LIBRARY_DIR}/board_options.sh" || exit 1
# shellcheck disable=SC2034,SC2154
EMERGE_BOARD_CMD="emerge-${BOARD}"

# Files to preserve from original stateful, if minimize_image is true.
# If minimize_image is false, everything is always preserved.
ALLOWLIST=(
  "vmlinuz_hd.vblock"
  "unencrypted/import_extensions"
  "unencrypted/dlc-factory-images"
)

get_install_vblock() {
  # If it exists, we need to copy the vblock over to stateful
  # This is the real vblock and not the recovery vblock.
  local partition_num_state stateful_mnt out

  partition_num_state=$(get_image_partition_number "${FLAGS_image}" "STATE")
  IMAGE_DEV=$(loopback_partscan "${FLAGS_image}")
  stateful_mnt=$(mktemp -d)
  out=$(mktemp)

  set +e
  sudo mount "${IMAGE_DEV}"p"${partition_num_state}" "${stateful_mnt}"
  sudo cp "${stateful_mnt}/vmlinuz_hd.vblock"  "${out}"
  sudo chown "${USER}" "${out}"

  safe_umount "${stateful_mnt}"
  rmdir "${stateful_mnt}"
  loopback_detach "${IMAGE_DEV}"
  switch_to_strict_mode
  echo "${out}"
}

calculate_kernel_hash() {
  local img="$1"

  local partition_num_kern_a kern_offset kern_size kern_tmp

  partition_num_kern_a="$(get_image_partition_number "${img}" "KERN-A")"
  kern_offset="$(partoffset "${img}" "${partition_num_kern_a}")"
  kern_size="$(partsize "${img}" "${partition_num_kern_a}")"
  kern_tmp=$(mktemp)

  dd if="${FLAGS_image}" bs=512 count="${kern_size}" \
     skip="${kern_offset}" of="${kern_tmp}" 1>&2
  # We're going to use the real signing block.
  if [[ "${FLAGS_sync_keys}" -eq "${FLAGS_TRUE}" ]]; then
    dd if="${INSTALL_VBLOCK}" of="${kern_tmp}" conv=notrunc 1>&2
  fi
  sha256sum "${kern_tmp}" | cut -f1 -d' '
  rm "${kern_tmp}"
}

create_recovery_kernel_image() {
  local sysroot="${FACTORY_ROOT}"
  local vmlinuz="${sysroot}/boot/vmlinuz"

  local enable_rootfs_verification_flag=--noenable_rootfs_verification
  if grep -q enable_rootfs_verification "${IMAGE_DIR}/boot.desc"; then
    enable_rootfs_verification_flag=--enable_rootfs_verification
  fi

  # Tie the installed recovery kernel to the final kernel.  If we don't
  # do this, a normal recovery image could be used to drop an unsigned
  # kernel on without a key-change check.
  # Doing this here means that the kernel and initramfs creation can
  # be done independently from the image to be modified as long as the
  # chromeos-recovery interfaces are the same.  It allows for the signer
  # to just compute the new hash and update the kernel command line during
  # recovery image generation.  (Alternately, it means an image can be created,
  # modified for recovery, then passed to a signer which can then sign both
  # partitions appropriately without needing any external dependencies.)

  local kern_hash
  kern_hash="$(calculate_kernel_hash "${FLAGS_image}")"

  # TODO(wad) add FLAGS_boot_args support too.
  # shellcheck source=build_kernel_image.sh
  # shellcheck disable=SC2154
  "${SCRIPTS_DIR}"/build_kernel_image.sh \
    --board="${FLAGS_board}" \
    --arch="${ARCH}" \
    --to="${RECOVERY_KERNEL_IMAGE}" \
    --vmlinuz="${vmlinuz}" \
    --working_dir="${IMAGE_DIR}" \
    --boot_args="noinitrd panic=60 cros_recovery kern_b_hash=${kern_hash}" \
    --enable_serial="${FLAGS_enable_serial}" \
    --keep_work \
    --keys_dir="${FLAGS_keys_dir}" \
    "${enable_rootfs_verification_flag}" \
    --public="recovery_key.vbpubk" \
    --private="recovery_kernel_data_key.vbprivk" \
    --keyblock="recovery_kernel.keyblock" 1>&2 || die "build_kernel_image"
}

update_efi_partition() {
  # Update the EFI System Partition configuration so that the kern_hash check
  # passes.
  local partition_num_efi_system efi_size kern_hash

  RECOVERY_DEV=$(loopback_partscan "${RECOVERY_IMAGE}")
  partition_num_efi_system=$(get_image_partition_number "${RECOVERY_IMAGE}" \
    "EFI-SYSTEM")

  efi_size=$(partsize "${RECOVERY_IMAGE}" "${partition_num_efi_system}")
  kern_hash="$(calculate_kernel_hash "${RECOVERY_IMAGE}")"

  if [[ ${efi_size} -ne 0 ]]; then
    local efi_dir

    efi_dir=$(mktemp -d)
    sudo mount "${RECOVERY_DEV}p${partition_num_efi_system}" "${efi_dir}"

    sudo sed  -i -e "s/cros_legacy/cros_legacy kern_b_hash=${kern_hash}/g" \
      "${efi_dir}/syslinux/usb.A.cfg" || true
    # This will leave the hash in the kernel for all boots, but that should be
    # safe.
    sudo sed  -i -e "s/cros_efi/cros_efi kern_b_hash=${kern_hash}/g" \
      "${efi_dir}/efi/boot/grub.cfg" || true
    safe_umount "${efi_dir}"
    rmdir "${efi_dir}"
  fi
  loopback_detach "${RECOVERY_DEV}"
}

install_recovery_kernel_once() {
  local kern_offset="$1"
  local kern_size="$2"

  local kernel_img_bytes
  kernel_img_bytes="$(stat -c %s "${RECOVERY_KERNEL_IMAGE}")"
  if [[ "${kernel_img_bytes}" -gt "$(( kern_size * 512 ))" ]]; then
    die "Kernel image size ($(( kernel_img_bytes / 1048576)) MiB) is " \
      "larger than kernel partition size ($(( kern_size * 512 / 1048576 )) MiB)"
  fi

  dd if="${RECOVERY_KERNEL_IMAGE}" of="${RECOVERY_IMAGE}" bs=512 \
     seek="${kern_offset}" \
     count="${kern_size}" \
     conv=notrunc
}

install_recovery_kernel() {
  local partition_num_kern_a kern_a_offset kern_a_size \
        partition_num_kern_b kern_b_offset kern_b_size \
        partition_num_kern_c kern_c_offset kern_c_size \
        has_kern_c

  partition_num_kern_a=$(get_image_partition_number "${RECOVERY_IMAGE}" \
    "KERN-A")
  kern_a_offset=$(partoffset "${RECOVERY_IMAGE}" "${partition_num_kern_a}")
  kern_a_size=$(partsize "${RECOVERY_IMAGE}" "${partition_num_kern_a}")

  partition_num_kern_b=$(get_image_partition_number "${RECOVERY_IMAGE}" \
    "KERN-B")
  kern_b_offset=$(partoffset "${RECOVERY_IMAGE}" "${partition_num_kern_b}")
  kern_b_size=$(partsize "${RECOVERY_IMAGE}" "${partition_num_kern_b}")

  if [ "${kern_b_size}" -eq 1 ]; then
    echo "Image was created with no KERN-B partition reserved!" 1>&2
    echo "Cannot proceed." 1>&2
    return 1
  fi

  # Only some devices have a KERN-C. If it exists and has size > 1 sector,
  # the same recovery kernel is installed as both KERN-A and KERN-C. If not,
  # the recovery kernel is installed as KERN-A only. (See b/266502803).
  has_kern_c="true"
  partition_num_kern_c=$(get_image_partition_number "${RECOVERY_IMAGE}" \
    "KERN-C")
  if [[ -z "${partition_num_kern_c}" ]]; then
    has_kern_c="false"
  else
    kern_c_offset=$(partoffset "${RECOVERY_IMAGE}" "${partition_num_kern_c}")
    kern_c_size=$(partsize "${RECOVERY_IMAGE}" "${partition_num_kern_c}")
    if [[ "${kern_c_size}" -le 1 ]]; then
      has_kern_c="false"
    fi
  fi

  # We're going to use the real signing block.
  if [ "${FLAGS_sync_keys}" -eq "${FLAGS_TRUE}" ]; then
    dd if="${INSTALL_VBLOCK}" of="${RECOVERY_IMAGE}" bs=512 \
       seek="${kern_b_offset}" \
       conv=notrunc
  fi

  install_recovery_kernel_once "${kern_a_offset}" "${kern_a_size}"
  if [[ "${has_kern_c}" == "true" ]]; then
    install_recovery_kernel_once "${kern_c_offset}" "${kern_c_size}"
  fi

  # Force all of the file writes to complete, in case it's necessary for
  # crbug.com/954188
  sync

  # Set the 'Success' flag to 1 (to prevent the firmware from updating
  # the 'Tries' flag).
  # shellcheck disable=SC2154
  sudo "${GPT}" add -i "${partition_num_kern_a}" -S 1 "${RECOVERY_IMAGE}"
  if [[ "${has_kern_c}" == "true" ]]; then
    sudo "${GPT}" add -i "${partition_num_kern_c}" -S 1 "${RECOVERY_IMAGE}"

    # Set the KERN-C priority non-zero, otherwise the firmware won't try it.
    sudo "${GPT}" add -i "${partition_num_kern_c}" -P 1 "${RECOVERY_IMAGE}"
  fi

  # Repeat for the legacy bioses.
  # Replace vmlinuz.A with the recovery version we built.
  # TODO(wad): Extract the $RECOVERY_KERNEL_IMAGE and grab vmlinuz from there.
  local sysroot vmlinuz failed
  sysroot="${FACTORY_ROOT}"
  vmlinuz="${sysroot}/boot/vmlinuz"
  failed=0

  if [ "${ARCH}" = "x86" ]; then
    RECOVERY_DEV=$(loopback_partscan "${RECOVERY_IMAGE}")
    # There is no syslinux on ARM, so this copy only makes sense for x86.
    local partition_num_efi_system esp_mnt

    set +e
    partition_num_efi_system=$(get_image_partition_number \
      "${RECOVERY_IMAGE}" "EFI-SYSTEM")
    esp_mnt=$(mktemp -d)
    sudo mount "${RECOVERY_DEV}"p"${partition_num_efi_system}" "${esp_mnt}"
    sudo cp "${vmlinuz}" "${esp_mnt}/syslinux/vmlinuz.A" || failed=1
    safe_umount "${esp_mnt}"
    rmdir "${esp_mnt}"
    loopback_detach "${RECOVERY_DEV}"
    switch_to_strict_mode
  fi

  if [ "${failed}" -eq 1 ]; then
    echo "Failed to copy recovery kernel to ESP"
    return 1
  fi
  return 0
}

find_sectors_needed() {
  # Find the minimum disk sectors needed for a file system to hold a list of
  # files or directories.
  local base_dir file_list in_use sectors_needed

  base_dir="$1"
  read -r -a file_list <<< "$2"

  # Calculate space needed by the files we'll be copying, plus
  # a reservation for recovery logs or other runtime data.
  in_use=$(cd "${base_dir}" || die "${base_dir} doesn't exists."
            du -s -B512 "${file_list[@]}" |
            awk '{ sum += $1 } END { print sum }')
  sectors_needed=$(( in_use + FLAGS_statefulfs_sectors ))

  # Add 10% overhead for the FS, rounded down.  There's some
  # empirical justification for this number, but at heart, it's a
  # wild guess.
  echo $(( sectors_needed + sectors_needed / 10 ))
}

# Copy the given list of files from old stateful partition to new stateful
# partition.
# Args:
#  $1: source image filename
#  $2: destination image filename
copy_stateful() {
  local src_img="$1"
  local dst_img="$2"

  local old_stateful_mnt sectors_needed
  local small_stateful new_stateful_mnt

  # Mount the old stateful partition so we can copy selected values
  # off of it.
  local partition_num_state
  partition_num_state=$(get_image_partition_number "${dst_img}" "STATE")
  old_stateful_mnt=$(mktemp -d)

  IMAGE_DEV=$(loopback_partscan "${src_img}")
  sudo mount "${IMAGE_DEV}p${partition_num_state}" "${old_stateful_mnt}"

  sectors_needed="$(cgpt show -i "${partition_num_state}" -n -s "${dst_img}")"

  # Rebuild the image with stateful partition sized by sectors_needed.
  small_stateful=$(mktemp)
  dd if=/dev/zero of="${small_stateful}" bs=512 \
    count="${sectors_needed}" 1>&2
  trap \
    'rm "${small_stateful}"; loopback_detach "${IMAGE_DEV}" || true; cleanup' \
    EXIT

  # Don't bother with ext3 for such a small image.
  /sbin/mkfs.ext2 -F -b 4096 "${small_stateful}" 1>&2

  # If it exists, we need to copy the vblock over to stateful
  # This is the real vblock and not the recovery vblock.
  new_stateful_mnt=$(mktemp -d)

  # Force all of the file writes to complete, in case it's necessary for
  # crbug.com/954188
  sync
  sudo mount -o loop "${small_stateful}" "${new_stateful_mnt}"

  # Create the directories that are going to be needed below. With correct
  # permissions and ownership.
  sudo mkdir --mode=755 "${new_stateful_mnt}/unencrypted"

  # Copy over any files that need to be preserved.
  for name in "${ALLOWLIST[@]}"; do
    if [ -e "${old_stateful_mnt}/${name}" ]; then
      sudo cp -a "${old_stateful_mnt}/${name}" "${new_stateful_mnt}/${name}"
    fi
  done

  # Cleanup everything.
  safe_umount "${old_stateful_mnt}"
  # Delete the loop device associated with this mount.
  safe_umount -d "${new_stateful_mnt}"
  rmdir "${old_stateful_mnt}"
  rmdir "${new_stateful_mnt}"
  loopback_detach "${IMAGE_DEV}"
  trap cleanup EXIT
  switch_to_strict_mode

  local dst_start
  dst_start="$(cgpt show -i "${partition_num_state}" -b "${dst_img}")"
  dd if="${small_stateful}" of="${dst_img}" conv=notrunc bs=512 \
    seek="${dst_start}" count="${sectors_needed}" status=none
  rm "${small_stateful}"
  return 0
}

# Calculates the number of sectors required for stateful partition.
# or returns the source stateful partition size if --minimize_image not present.
calculate_stateful_blocks() {
  local partition_num_state
  partition_num_state="$(get_image_partition_number "${FLAGS_image}" "STATE")"

  # If --minimize_image not present, use the partition size from source image,
  # (not recovery image, it's hard-coded to 2MiB).
  if [[ "${FLAGS_minimize_image}" -eq "${FLAGS_FALSE}" ]]; then
    cgpt show -i "${partition_num_state}" -n -s "${FLAGS_image}"
    return 0
  fi

  local old_stateful_mnt
  old_stateful_mnt="$(mktemp -d)"

  IMAGE_DEV=$(loopback_partscan "${FLAGS_image}")
  sudo mount "${IMAGE_DEV}p${partition_num_state}" "${old_stateful_mnt}"

  # Print the minimum number of sectors needed.
  find_sectors_needed "${old_stateful_mnt}" "${ALLOWLIST[*]}"

  # Cleanup everything.
  safe_umount "${old_stateful_mnt}"
  rmdir "${old_stateful_mnt}"
  loopback_detach "${IMAGE_DEV}"

  return 0
}

# Creates an empty image using the recovery layout and calculated stateful size.
create_image() {
  local dst_img="$1"

  local stateful_blocks
  stateful_blocks="$(calculate_stateful_blocks)"

  # Remove dst_img first otherwise build_gpt_image won't create a new one
  # with correct layout.
  rm -f "${dst_img}"

  # Build the partition table.
  local partition_script_path
  partition_script_path="$(dirname "${dst_img}")/partition_script.sh"
  write_partition_script recovery "${partition_script_path}" \
    "STATE:=$(( stateful_blocks * 512 ))"
  run_partition_script "${dst_img}" "${partition_script_path}"
}

# Copy the partitions one by one from source image to destination image,
# except that KERN-A is moved to KERN-B.
# Args:
#  $1: source image filename
#  $2: destination image filename
copy_partitions() {
  local src_img="$1"
  local dst_img="$2"

  local part
  for part in $("${GPT}" show -n -q "${src_img}" | awk '{print $3}'); do
    # Load source partition details.
    local size label
    size="$(cgpt show -i "${part}" -s "${src_img}")"
    label="$(cgpt show -i "${part}" -l "${src_img}")"
    if [[ "${size}" -eq 0 ]]; then
      continue
    fi

    local dst_part="${part}"
    # Move KERN-A to KERN-B.
    if [[ ${label} == 'KERN-A' ]]; then
      dst_part="$(get_image_partition_number "${dst_img}" 'KERN-B')"
    fi

    local dst_start dst_size
    dst_start="$(cgpt show -i "${dst_part}" -b "${dst_img}")"
    dst_size="$(cgpt show -i "${dst_part}" -s "${dst_img}")"

    if [[ "${label}" == 'STATE' && \
          "${FLAGS_minimize_image}" -eq "${FLAGS_TRUE}" ]]; then
      copy_stateful "${src_img}" "${dst_img}"
    elif [[ ${label} == 'KERN-B' ]]; then
      : # Skip KERN-B.
    else
      # Copy other partition as-is.
      if [[ "${size}" -gt "${dst_size}" ]]; then
        die "Partition #${part} larger than the destination partition"
      fi
      local src_start
      src_start="$(cgpt show -i "${part}" -b "${src_img}")"
      dd if="${src_img}" of="${dst_img}" conv=notrunc bs=512 \
         skip="${src_start}" seek="${dst_start}" count="${size}" \
         status=none
      sync
    fi
  done
  return 0
}

cleanup() {
  set +e
  if [[ -n "${RECOVERY_DEV}" ]]; then
    loopback_detach "${RECOVERY_DEV}" || true
  fi
  if [[ -n "${IMAGE_DEV}" ]]; then
    loopback_detach "${IMAGE_DEV}" || true
  fi
  if [[ "${FLAGS_image}" != "${RECOVERY_IMAGE}" ]]; then
    rm "${RECOVERY_IMAGE}"
  fi
  rm "${INSTALL_VBLOCK}"
}


# Main process begins here.
set -u

# No image was provided, use standard latest image path.
if [ -z "${FLAGS_image}" ]; then
  # Ignore SC2153, since IMAGES_DIR is defined in common.sh
  # shellcheck disable=SC2153,SC2154
  FLAGS_image="${IMAGES_DIR}/${BOARD}/latest/${CHROMEOS_IMAGE_NAME}"
fi

# Turn path into an absolute path.
FLAGS_image=$(readlink -f "${FLAGS_image}")

# Abort early if we can't find the image.
if [ ! -f "${FLAGS_image}" ]; then
  die_notrace "Image not found: ${FLAGS_image}"
fi

IMAGE_DIR="$(dirname "${FLAGS_image}")"
RECOVERY_IMAGE="${FLAGS_to:-${IMAGE_DIR}/${CHROMEOS_RECOVERY_IMAGE_NAME}}"
RECOVERY_KERNEL_IMAGE=\
"${FLAGS_kernel_outfile:-${IMAGE_DIR}/${RECOVERY_KERNEL_NAME}}"
SCRIPTS_DIR="${SCRIPT_ROOT}"
RECOVERY_DEV=""
IMAGE_DEV=""

if [ "${FLAGS_kernel_image_only}" -eq "${FLAGS_TRUE}" ] && \
  [ -n "${FLAGS_kernel_image}" ]; then
  die_notrace "Cannot use --kernel_image_only with --kernel_image"
fi

echo "Creating recovery image from ${FLAGS_image}"

INSTALL_VBLOCK=$(get_install_vblock)
if [ -z "${INSTALL_VBLOCK}" ]; then
  die "Could not copy the vblock from stateful."
fi

# shellcheck disable=SC2154
FACTORY_ROOT="${BOARD_ROOT}/factory-root"
: "${USE:=}"

if [ -z "${FLAGS_kernel_image}" ]; then
  # Build the recovery kernel.
  RECOVERY_KERNEL_FLAGS="recovery_ramfs tpm i2cdev vfat kernel_compress_xz"
  RECOVERY_KERNEL_FLAGS="${RECOVERY_KERNEL_FLAGS} -kernel_afdo -kern_arm_afdo"
  USE="${USE} ${RECOVERY_KERNEL_FLAGS}" emerge_custom_kernel "${FACTORY_ROOT}" \
    || die "Cannot emerge custom kernel"
  create_recovery_kernel_image
  echo "Recovery kernel created at ${RECOVERY_KERNEL_IMAGE}"
else
  RECOVERY_KERNEL_IMAGE="${FLAGS_kernel_image}"
fi

if [ "${FLAGS_kernel_image_only}" -eq "${FLAGS_TRUE}" ]; then
  echo "Kernel emitted. Stopping there."
  rm "${INSTALL_VBLOCK}"
  exit 0
fi

trap cleanup EXIT

if [[ "${FLAGS_modify_in_place}" -eq "${FLAGS_TRUE}" ]]; then
  # Implement in-place modification by creating a temp image and copy it back
  # to the source image path later.
  RECOVERY_IMAGE="$(mktemp)"
fi
create_image "${RECOVERY_IMAGE}"
copy_partitions "${FLAGS_image}" "${RECOVERY_IMAGE}"
sync

if [ "${FLAGS_decrypt_stateful}" -eq "${FLAGS_TRUE}" ]; then
  stateful_mnt=$(mktemp -d)
  RECOVERY_DEV=$(loopback_partscan "${RECOVERY_IMAGE}")
  partition_num_state=$(get_image_partition_number \
    "${RECOVERY_IMAGE}" "STATE")
  sudo mount "${RECOVERY_DEV}p${partition_num_state}" "${stateful_mnt}"
  echo -n "1" | sudo tee "${stateful_mnt}"/decrypt_stateful >/dev/null
  sudo umount "${stateful_mnt}"
  rmdir "${stateful_mnt}"
  loopback_detach "${RECOVERY_DEV}"
fi

install_recovery_kernel
update_efi_partition

if [[ "${FLAGS_modify_in_place}" -eq "${FLAGS_TRUE}" ]]; then
  mv "${RECOVERY_IMAGE}" "${FLAGS_image}"
fi

echo "Recovery image created at ${RECOVERY_IMAGE}"
command_completed
trap - EXIT
