#!/bin/bash

# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Helper script that mounts chromium os image from a device or directory
# and creates mount points for /var and /usr/local (if in dev_mode).

# Helper scripts should be run from the same location as this script.
echo "Entering $0 $*" >&2

SCRIPT_ROOT=$(dirname "$(readlink -f "$0")")
. "${SCRIPT_ROOT}/common.sh" || exit 1
. "${SCRIPT_ROOT}/build_library/filesystem_util.sh" || exit 1
. "${SCRIPT_ROOT}/build_library/disk_layout_util.sh" || exit 1
. "${SCRIPT_ROOT}/build_library/ext2_sb_util.sh" || exit 1

if [[ ${INSIDE_CHROOT} -ne 1 ]]; then
  INSTALL_ROOT="${SRC_ROOT}/platform2/chromeos-common-script/share"
else
  INSTALL_ROOT=/usr/share/misc
fi
# Load functions and constants for chromeos-install
. "${INSTALL_ROOT}/chromeos-common.sh" || exit 1

locate_gpt

# Default value for FLAGS_image.
DEFAULT_IMAGE="chromiumos_image.bin"

# Flags.
DEFINE_string board "$DEFAULT_BOARD" \
  "The board for which the image was built." b
DEFINE_boolean read_only ${FLAGS_FALSE} \
  "Mount in read only mode -- skips stateful items."
DEFINE_boolean safe ${FLAGS_FALSE} \
  "Mount rootfs in read only mode."
DEFINE_boolean unmount ${FLAGS_FALSE} \
  "Unmount previously mounted image." u
DEFINE_string from "" \
  "Directory, image, or device with image on it" f
DEFINE_string image "${DEFAULT_IMAGE}" \
  "Name of the bin file if a directory is specified in the from flag" i
DEFINE_string partition_script "partition_script.sh" \
  "Name of the script with the partition layout if a directory is specified"
DEFINE_string rootfs_mountpt "/tmp/m" "Mount point for rootfs" r
DEFINE_string stateful_mountpt "/tmp/s" \
  "Mount point for stateful partition" s
DEFINE_string esp_mountpt "" \
  "Mount point for esp partition" e
DEFINE_boolean delete_mountpts ${FLAGS_FALSE} \
  "Delete the mountpoint directories when unmounting."
DEFINE_boolean most_recent ${FLAGS_FALSE} "Use the most recent image dir" m
DEFINE_string local_build_dir "/build" \
  "Temporary root directory (under the sysroot) where ebuilds can install "\
"temporary files during the build."

# Parse flags
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Die on error
switch_to_strict_mode

# We don't accept any positional args, so reject to catch typos.
if [[ $# -ne 0 ]]; then
  die_notrace "${SCRIPT_NAME} takes no arguments; given: $*"
fi

# Find the last image built on the board.
if [[ ${FLAGS_most_recent} -eq ${FLAGS_TRUE} ]] ; then
  FLAGS_from="${IMAGES_DIR}/${FLAGS_board}/latest"
fi

# If --from is a block device, --image can't also be specified.
if [[ -b "${FLAGS_from}" ]]; then
  if [[ "${FLAGS_image}" != "${DEFAULT_IMAGE}" ]]; then
    die_notrace "-i ${FLAGS_image} can't be used with block device ${FLAGS_from}"
  fi
fi

# Allow --from /foo/file.bin
if [[ -f "${FLAGS_from}" ]]; then
  # If --from is specified as a file, --image cannot be also specified.
  if [[ "${FLAGS_image}" != "${DEFAULT_IMAGE}" ]]; then
    die_notrace "-i ${FLAGS_image} can't be used with --from file ${FLAGS_from}"
  fi
  # The order is important here. We want to override FLAGS_image before
  # destroying FLAGS_from.
  FLAGS_image="$(basename "${FLAGS_from}")"
  FLAGS_from="$(dirname "${FLAGS_from}")"
fi

# Fixes symlinks that are incorrectly prefixed with the build root $1
# rather than the real running root '/'.
fix_broken_symlinks() {
  local build_root=$1
  local symlinks=$(find "${build_root}/usr/local" -lname "${build_root}/*")
  local symlink
  for symlink in ${symlinks}; do
    echo "Fixing ${symlink}"
    local target=$(ls -l "${symlink}" | cut -f 2 -d '>')
    # Trim spaces from target (bashism).
    target=${target/ /}
    # Make new target (removes rootfs prefix).
    new_target=$(echo ${target} | sed "s#${build_root}##")

    echo "Fixing symlink ${symlink}"
    sudo unlink "${symlink}"
    sudo ln -sf "${new_target}" "${symlink}"
  done
}

load_image_partition_numbers() {
  local partition_script="${FLAGS_from}/${FLAGS_partition_script}"
  # Attempt to load the partition script from the rootfs when not found in the
  # FLAGS_from directory.
  if [[ ! -f "${partition_script}" ]]; then
    partition_script="${FLAGS_rootfs_mountpt}/${PARTITION_SCRIPT_PATH}"
  fi
  if [[ -f "${partition_script}" ]]; then
    . "${partition_script}"
    load_partition_vars
    return
  fi

  # Without a partition script, infer numbers from the payload image.
  local image
  if [[ -b "${FLAGS_from}" ]]; then
    image="${FLAGS_from}"
  elif [[ -n "${FLAGS_from}" ]]; then
    image="${FLAGS_from}/${FLAGS_image}"
    if [[ ! -f "${image}" ]]; then
      die "Image ${image} does not exist."
    fi
  fi
  PARTITION_NUM_STATE="$(get_image_partition_number "${image}" "STATE")"
  PARTITION_NUM_ROOT_A="$(get_image_partition_number "${image}" "ROOT-A")"
  PARTITION_NUM_OEM="$(get_image_partition_number "${image}" "OEM")"
  PARTITION_NUM_EFI_SYSTEM="$(get_image_partition_number "${image}" \
    "EFI-SYSTEM")"
}

unmount_local_build_root() {
  local build_dir="${FLAGS_rootfs_mountpt}/${FLAGS_local_build_dir}"
  local rootfs="${build_dir}/rootfs"
  info "Unmounting temporary rootfs ${rootfs}."
  if [[ -d "${rootfs}" ]]; then
    sudo umount "${rootfs}"
    sudo rmdir "${rootfs}"
  fi
  if [[ -d "${build_dir}" ]]; then
    sudo rmdir "${build_dir}"
  fi
  sudo rm -rf "${LOCAL_BUILDROOT_MOUNTPOINT}"
}

# Common unmounts for either a device or directory
unmount_image() {
  info "Unmounting image from ${FLAGS_stateful_mountpt}" \
      "and ${FLAGS_rootfs_mountpt}"
  # Don't die on error to force cleanup
  set +e

  if [[ ${FLAGS_read_only} -eq ${FLAGS_FALSE} ]]; then
    if [[ ${FLAGS_safe} -eq ${FLAGS_FALSE} ]]; then
      unmount_local_build_root
    fi
  fi

  # Reset symlinks in /usr/local.
  if mount | egrep -q ".* ${FLAGS_stateful_mountpt} .*\(rw,"; then
    setup_symlinks_on_root "." "/var" "${FLAGS_stateful_mountpt}"
    fix_broken_symlinks "${FLAGS_rootfs_mountpt}"
  fi

  local loopdev
  local filename
  if [[ -b "${FLAGS_from}" ]]; then
    filename="${FLAGS_from}"
  elif [[ -n "${FLAGS_from}" ]]; then
    filename="${FLAGS_from}/${FLAGS_image}"
    if [[ ! -f "${filename}" ]]; then
      die "Image ${filename} does not exist."
    fi
  fi
  if [[ -z "${filename}" ]]; then
    warn "Umount called without passing the image. Some filesystems can't" \
         "be unmounted in this way."
  else
    loopdev="$(loopback_partscan "${filename}")"
  fi

  # Unmount in reverse order: EFI, OEM, stateful and rootfs.
  local var_name mountpoint fs_format fs_options
  local part_label part_num part_loop
  for part_label in EFI_SYSTEM OEM STATE ROOT_A; do
    var_name="${part_label}_MOUNTPOINT"
    mountpoint="${!var_name}"
    [[ -n "${mountpoint}" ]] || continue
    var_name="PARTITION_NUM_${part_label}"
    part_num="${!var_name}"
    if [[ -z "${part_num}" ]]; then
      # Depending on how it was mounted, clear all existing mounts.
      sudo umount -R "${mountpoint}"
      continue
    fi
    part_loop="${loopdev}p${part_num}"

    if [[ -z "${filename}" ]]; then
      # TODO(deymo): Remove this legacy umount.
      if ! mountpoint -q "${mountpoint}"; then
        die "You must pass --image or --from when using --unmount to unmount" \
          "this image."
      fi
      safe_umount_tree "${mountpoint}"
      continue
    fi

    # Get the variables loaded with load_partition_vars during mount_*.
    var_name="FS_FORMAT_${part_num}"
    fs_format="${!var_name}"
    var_name="FS_OPTIONS_${part_num}"
    fs_options="${!var_name}"

    fs_umount "${part_loop}" "${mountpoint}" "${fs_format}" "${fs_options}"
  done

  if [[ -n "${loopdev}" ]]; then
    sudo losetup -d "${loopdev}"
  fi

  # We need to remove the mountpoints after we unmount all the partitions since
  # there could be nested mounts.
  if [[ ${FLAGS_delete_mountpts} -eq ${FLAGS_TRUE} ]]; then
    for part_label in EFI_SYSTEM OEM STATE ROOT_A; do
      var_name="${part_label}_MOUNTPOINT"
      mountpoint="${!var_name}"
      # Check this is a directory.
      [[ -n "${mountpoint}" && -d "${mountpoint}" ]] || continue
      fs_remove_mountpoint "${mountpoint}"
    done
  fi

  switch_to_strict_mode
}

mount_usb_partitions() {
  local ro_rw="rw"
  local rootfs_ro_rw="rw"
  if [[ ${FLAGS_read_only} -eq ${FLAGS_TRUE} ]]; then
    ro_rw="ro"
  fi
  if [[ ${FLAGS_read_only} -eq ${FLAGS_TRUE} ||
        ${FLAGS_safe} -eq ${FLAGS_TRUE} ]]; then
    rootfs_ro_rw="ro"
  fi

  if [[ -f "${FLAGS_from}/${FLAGS_partition_script}" ]]; then
    . "${FLAGS_from}/${FLAGS_partition_script}"
    load_partition_vars
  fi

  fs_mount "${FLAGS_from}${PARTITION_NUM_ROOT_A}" "${ROOT_A_MOUNTPOINT}" \
    "${FS_FORMAT_ROOT_A}" "${rootfs_ro_rw}"
  fs_mount "${FLAGS_from}${PARTITION_NUM_STATE}" "${STATE_MOUNTPOINT}" \
    "${FS_FORMAT_STATE}" "${ro_rw}"
  fs_mount "${FLAGS_from}${PARTITION_NUM_OEM}" "${OEM_MOUNTPOINT}" \
    "${FS_FORMAT_OEM}" "${ro_rw}"

  if [[ -n "${FLAGS_esp_mountpt}" && \
        -e ${FLAGS_from}${PARTITION_NUM_EFI_SYSTEM} ]]; then
    fs_mount "${FLAGS_from}${PARTITION_NUM_EFI_SYSTEM}" \
      "${EFI_SYSTEM_MOUNTPOINT}" "${FS_FORMAT_EFI_SYSTEM}" "${ro_rw}"
  fi
}

mount_gpt_partitions() {
  local filename="${FLAGS_from}/${FLAGS_image}"

  local ro_rw="rw"
  if [[ ${FLAGS_read_only} -eq ${FLAGS_TRUE} ]]; then
    ro_rw="ro"
  fi

  if [[ ! -f "${filename}" ]]; then
    die "Image ${filename} does not exist."
  fi

  if [[ -f "${FLAGS_from}/${FLAGS_partition_script}" ]]; then
    . "${FLAGS_from}/${FLAGS_partition_script}"
    load_partition_vars
  fi

  local loopdev="$(loopback_partscan "${filename}")"

  # Mount in order: rootfs, stateful, OEM and EFI.
  local var_name mountpoint fs_format
  local part_label part_num part_loop part_ro_rw
  for part_label in ROOT_A STATE OEM EFI_SYSTEM; do
    var_name="${part_label}_MOUNTPOINT"
    mountpoint="${!var_name}"
    [[ -n "${mountpoint}" ]] || continue

    var_name="PARTITION_NUM_${part_label}"
    part_num="${!var_name}"
    [[ -n "${part_num}" ]] || continue
    part_loop="${loopdev}p${part_num}"

    var_name="FS_FORMAT_${part_num}"
    fs_format="${!var_name}"

    # For the rootfs, make sure it's writable so callers can modify it,
    # unless the caller explicitly requested otherwise.
    # cros_make_image_bootable should restore the bit if needed.
    part_ro_rw="${ro_rw}"
    if [[ "${part_label}" == ROOT_* ]]; then
      if [[ ${FLAGS_safe} -eq ${FLAGS_TRUE} ]]; then
        part_ro_rw="ro"
      elif [[ ${FLAGS_read_only} -eq ${FLAGS_FALSE} ]]; then
        enable_rw_mount "${part_loop}"
      fi
    fi

    if ! fs_mount "${part_loop}" "${mountpoint}" "${fs_format}" \
        "${part_ro_rw}"; then
      error "mount failed: image=${filename} device=${part_loop}" \
        "target=${mountpoint} format=${fs_format} ro/rw=${part_ro_rw}"
      sudo losetup -d "${loopdev}"
      return 1
    fi
  done

  # Detach the loopback now even though we have mounts.  This way when the last
  # mount is freed, the kernel will automatically release the loopback.
  sudo losetup -d "${loopdev}"
}

# Create a local buildroot that can be used by ebuilds that need to install
# temporary files during the build even though those files should not be in the
# final image. This is typically the case of ebuilds that install files to
# Android's /vendor directory before board_specific_setup repacks them to the
# final vendor image. Those ebuilds can instead install files to
# /build/rootfs/opt/google/containers/.../vendor where board_specific_setup
# will pick them up and add them to the final vendor image.
# To avoid running out of space in the root partition during the build, use a
# separate directory outside of the image and bindmount it to the local
# buildroot.
mount_local_build_root() {
  local build_dir="${FLAGS_rootfs_mountpt}/${FLAGS_local_build_dir}"
  local rootfs="${build_dir}/rootfs"
  if [[ ! -d "${rootfs}" ]]; then
    sudo mkdir -p "${rootfs}"
  fi
  info "Mounting temporary rootfs ${LOCAL_BUILDROOT_MOUNTPOINT} to ${rootfs}."
  if [[ ! -d "${LOCAL_BUILDROOT_MOUNTPOINT}" ]]; then
    sudo mkdir -p "${LOCAL_BUILDROOT_MOUNTPOINT}"
  fi
  sudo mount --bind "${LOCAL_BUILDROOT_MOUNTPOINT}" "${rootfs}"
}

# Mount a gpt based image.
mount_image() {
  mkdir -p "${FLAGS_rootfs_mountpt}"
  mkdir -p "${FLAGS_stateful_mountpt}"
  if [[ -n "${FLAGS_esp_mountpt}" ]]; then
    mkdir -p "${FLAGS_esp_mountpt}"
  fi
  # Get the partitions for the image / device.
  if [[ -b "${FLAGS_from}" ]]; then
    mount_usb_partitions
  elif ! mount_gpt_partitions; then
    echo "Current loopback device status:"
    sudo losetup --all | sed 's/^/    /'
    die "Failed to mount all partitions in ${FLAGS_from}/${FLAGS_image}"
  fi

  # Mount directories and setup symlinks.  Create dirs on demand in case they
  # were wiped out for some reason (devs like to dev!).
  mkdir_and_mount() {
    local src="$1" dst="$2"
    if [[ ! -d "${src}" ]]; then
      sudo mkdir "${src}"
    fi
    if [[ ! -d "${dst}" ]]; then
      sudo mkdir "${dst}"
    fi
    sudo mount --bind "${src}" "${dst}"
  }
  mkdir_and_mount "${FLAGS_stateful_mountpt}" \
    "${FLAGS_rootfs_mountpt}/mnt/stateful_partition"
  mkdir_and_mount "${FLAGS_stateful_mountpt}/var_overlay" \
    "${FLAGS_rootfs_mountpt}/var"
  mkdir_and_mount "${FLAGS_stateful_mountpt}/dev_image" \
    "${FLAGS_rootfs_mountpt}/usr/local"

  if [[ ${FLAGS_read_only} -eq ${FLAGS_FALSE} ]]; then
    if [[ ${FLAGS_safe} -eq ${FLAGS_FALSE} ]]; then
      mount_local_build_root
    fi
    # Setup symlinks in /usr/local so you can emerge packages into /usr/local.
    setup_symlinks_on_root "." \
      "${FLAGS_stateful_mountpt}/var_overlay" "${FLAGS_stateful_mountpt}"
  fi
  info "Image specified by ${FLAGS_from} mounted at"\
    "${FLAGS_rootfs_mountpt} successfully."
}

# Turn paths into absolute paths.
[[ -n "${FLAGS_from}" ]] && FLAGS_from="$(readlink -f "${FLAGS_from}")"
FLAGS_rootfs_mountpt="$(readlink -f "${FLAGS_rootfs_mountpt}")"
FLAGS_stateful_mountpt="$(readlink -f "${FLAGS_stateful_mountpt}")"

# Partition mountpoints based on the flags.
ROOT_A_MOUNTPOINT="${FLAGS_rootfs_mountpt}"
STATE_MOUNTPOINT="${FLAGS_stateful_mountpt}"
OEM_MOUNTPOINT="${FLAGS_rootfs_mountpt}/usr/share/oem"
EFI_SYSTEM_MOUNTPOINT="${FLAGS_esp_mountpt}"
LOCAL_BUILDROOT_MOUNTPOINT="${FLAGS_rootfs_mountpt}-local-build-dir"

# Read the image partition numbers from the GPT.
load_image_partition_numbers

# Perform desired operation.
if [[ ${FLAGS_unmount} -eq ${FLAGS_TRUE} ]]; then
  unmount_image
else
  mount_image
fi
