#!/bin/bash

# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Helper script that generates the legacy/efi bootloader partitions.
# It does not populate the templates, but can update a loop device.

SCRIPT_ROOT="$(dirname "$(readlink -f "$0")")"
# shellcheck source=common.sh
. "${SCRIPT_ROOT}/common.sh" || exit 1
# shellcheck source=build_library/disk_layout_util.sh
. "${BUILD_LIBRARY_DIR}/disk_layout_util.sh" || exit 1

# Need to be inside the chroot to load chromeos-common.sh
assert_inside_chroot

# Load functions and constants for chromeos-install
# shellcheck source=../../platform2/chromeos-common-script/share/chromeos-common.sh
. /usr/share/misc/chromeos-common.sh || exit 1

# Flags.
DEFINE_string arch "x86" \
  "The boot architecture: arm, mips, x86, or amd64 (Default: x86)"
DEFINE_string board "${DEFAULT_BOARD}" \
  "Board we're building for."
DEFINE_string image_type "usb" \
  "Type of image we're building for."
# TODO(wad) once extlinux is dead, we can remove this.
DEFINE_boolean install_syslinux ${FLAGS_FALSE} \
  "Controls whether syslinux is run on 'to'. (Default: false)"
DEFINE_string from "/tmp/boot" \
  "Path the legacy bootloader templates are copied from. (Default /tmp/boot)"
DEFINE_string to "/tmp/esp.img" \
  "Path to esp image (Default: /tmp/esp.img)"
# offset= interacts with dirty pages in the file in a very poor manner.  See
# crbug.com/954188. Use device partitions on the loop device instead.
#DEFINE_integer to_offset 0 \
#  "Offset in bytes into 'to' if it is a file (Default: 0)"
#DEFINE_integer to_size -1 \
#  "Size in bytes of 'to' to use if it is a file. -1 is ignored. (Default: -1)"
DEFINE_integer to_partition -1 \
  "Partition number to use on block device. -1 is ignored. (Default: -1)"
DEFINE_string vmlinuz "/tmp/vmlinuz" \
  "Path to the vmlinuz file to use (Default: /tmp/vmlinuz)"
DEFINE_string zimage "/tmp/zImage" \
  "Path to the zimage file to use (Default: /tmp/zImage)"
# The kernel_partition and the kernel_cmdline each are used to supply
# verified boot configuration: dm="".
DEFINE_string kernel_partition "/tmp/vmlinuz.image" \
  "Path to the signed kernel image. (Default: /tmp/vmlinuz.image)"
DEFINE_string kernel_cmdline "" \
  "Kernel commandline if no kernel_partition given. (Default: '')"
DEFINE_string kernel_partition_offset "0" \
  "Offset to the kernel partition [KERN-A] (Default: 0)"
DEFINE_string kernel_partition_sectors "0" \
  "Kernel partition sectors (Default: 0)"

# Parse flags
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"
switch_to_strict_mode

# shellcheck source=build_library/board_options.sh
. "${BUILD_LIBRARY_DIR}/board_options.sh" || exit 1

part_index_to_uuid() {
  local image="$1"
  local index="$2"
  cgpt show -i "$index" -u "$image"
}

# Common logic on x86/arm64 to replace placeholders in bootloader configs.
update_bootloaders() {
  local old_root="$1"  # e.g., /dev/sd%D%P or %U+1
  local kernel_cmdline="$2"
  local esp_fs_dir="$3"
  local template_dir="$4"
  local to="$5"

  # Pull out the dm="" values
  dm_table=
  if echo "$kernel_cmdline" | grep -q 'dm="'; then
    dm_table=$(echo "$kernel_cmdline" | sed -s 's/.*dm="\([^"]*\)".*/\1/')
  fi

  # Discover last known partition numbers.
  local partition_num_root_a="$(get_layout_partition_number \
    "${FLAGS_image_type}" ROOT-A)"
  local partition_num_root_b="$(get_layout_partition_number \
    "${FLAGS_image_type}" ROOT-B)"
  root_a_uuid="PARTUUID=$(part_index_to_uuid "$to" ${partition_num_root_a})"
  root_b_uuid="PARTUUID=$(part_index_to_uuid "$to" ${partition_num_root_b})"

  # Rewrite grub table
  grub_dm_table_a=${dm_table//${old_root}/${root_a_uuid}}
  grub_dm_table_b=${dm_table//${old_root}/${root_b_uuid}}
  sed -e "s|DMTABLEA|${grub_dm_table_a}|g" \
      -e "s|DMTABLEB|${grub_dm_table_b}|g" \
      -e "s|/dev/\\\$linuxpartA|${root_a_uuid}|g" \
      -e "s|/dev/\\\$linuxpartB|${root_b_uuid}|g" \
      -e "s|HDROOTUSB|${root_a_uuid}|g" \
      "${template_dir}"/efi/boot/grub.cfg |
      sudo dd of="${esp_fs_dir}"/efi/boot/grub.cfg status=none

  if [[ ${FLAGS_install_syslinux} -eq ${FLAGS_TRUE} ]]; then
    # Rewrite syslinux DM_TABLE and HDROOTUSB for USB booting.
    syslinux_dm_table_usb=${dm_table//${old_root}/${root_a_uuid}}
    sed -e "s|DMTABLEA|${syslinux_dm_table_usb}|g" \
        -e "s|HDROOTUSB|${root_a_uuid}|g" \
        "${template_dir}"/syslinux/usb.A.cfg |
        sudo dd of="${esp_fs_dir}"/syslinux/usb.A.cfg status=none
  fi

  # Note DMTABLE for root.A and root.B does not need to be updated because
  # postinst will discard all changes in EFI partition and copy from
  # rootfs:boot/syslinux/root.?.cfg again after installation or AU, because
  # new rootfs will be apparently different.

  # The only work left for the installer is to pick the correct defaults
  # and replace HDROOTA and HDROOTB with the correct /dev/sd%D%P/%U+1
}

ESP_DEV_OURS=
ESP_DEV=
if [[ ! -e "${FLAGS_to}" ]]; then
  error "The ESP doesn't exist"
  # This shouldn't happen.
  info "Creating a new esp image at ${FLAGS_to}" anyway.
  # Create EFI System Partition to boot stock EFI BIOS (but not ChromeOS EFI
  # BIOS).  ARM uses this space to determine which partition is bootable.
  # NOTE: The size argument for mkfs.vfat is in 1024-byte blocks.
  # We'll hard-code it to 16M for now.
  ESP_BLOCKS=16384
  /usr/sbin/mkfs.vfat -C "${FLAGS_to}" ${ESP_BLOCKS}
  ESP_DEV=$(sudo losetup --show -f "${FLAGS_to}")
  ESP_DEV_OURS=y
  if [ -z "${ESP_DEV}" ]; then
    die "No free loop devices."
  fi
else
  if [[ -f "${FLAGS_to}" ]]; then
    ESP_DEV=$(sudo losetup --show -f "${FLAGS_to}")
    ESP_DEV_OURS=y
    if [ -z "${ESP_DEV}" ]; then
      die "No free loop devices."
    fi
  else
    # If it is a block device or something else, try to mount it anyway.
    ESP_DEV="${FLAGS_to}"
    if [ ${FLAGS_to_partition} -ge 0 ]; then
      ESP_DEV="${ESP_DEV}"p"${FLAGS_to_partition}"
    fi
  fi
fi

ESP_FS_DIR=$(mktemp -d /tmp/esp.XXXXXX)
cleanup() {
  set +e
  if ! safe_umount "${ESP_FS_DIR}"; then
      # There is a race condition possible on some ubuntu setups
      # with mounting and unmounting a device very quickly
      # Doing a quick sleep/retry as a temporary workaround
      warn "Initial unmount failed. Possibly crosbug.com/23443. Retrying"
      sleep 5
      safe_umount "${ESP_FS_DIR}"
  fi
  if [[ -n "${ESP_DEV_OURS}" && -z "${ESP_DEV//\/dev\/loop*}" ]]; then
    sudo losetup -d  "${ESP_DEV}"
  fi
  rm -rf "${ESP_FS_DIR}"
}
trap cleanup EXIT
sudo mount "${ESP_DEV}" "${ESP_FS_DIR}"

if [[ "${FLAGS_arch}" == "x86" || "${FLAGS_arch}" == "amd64" || \
      ( "${FLAGS_arch}" == "arm64" && \
        -d "/build/${FLAGS_board}/lib64/grub/arm64-efi/" ) ]]; then
  # Populate the EFI bootloader configuration
  sudo mkdir -p "${ESP_FS_DIR}/efi/boot"
  sudo cp -r "${FLAGS_from}"/efi/boot/. "${ESP_FS_DIR}"/efi/boot

  # Prepopulate the syslinux directories too and update for verified boot values
  # after the rootfs work is done.
  sudo mkdir -p "${ESP_FS_DIR}"/syslinux
  sudo cp -r "${FLAGS_from}"/syslinux/. "${ESP_FS_DIR}"/syslinux

  # Stage both kernels with the only one we built.
  sudo cp -f "${FLAGS_vmlinuz}" "${ESP_FS_DIR}"/syslinux/vmlinuz.A
  sudo cp -f "${FLAGS_vmlinuz}" "${ESP_FS_DIR}"/syslinux/vmlinuz.B

  # Extract kernel flags
  kernel_cfg=
  old_root='PARTUUID=%U/PARTNROFF=1'
  if [[ -n "${FLAGS_kernel_cmdline}" ]]; then
    info "Using supplied kernel_cmdline to update templates."
    kernel_cfg="${FLAGS_kernel_cmdline}"
  elif [[ -n "${FLAGS_kernel_partition}" ]]; then
    info "Extracting the kernel command line from ${FLAGS_kernel_partition}"
    kernel_cfg=$(dump_kernel_config "${FLAGS_kernel_partition}")
  fi

  update_bootloaders "${old_root}" \
                     "${kernel_cfg}" \
                     "${ESP_FS_DIR}" \
                     "${FLAGS_from}" \
                     "${FLAGS_to}"

  # Install the syslinux loader on the ESP image (part 12) so it is ready when
  # we cut over from rootfs booting (extlinux).
  if [[ ${FLAGS_install_syslinux} -eq ${FLAGS_TRUE} ]]; then
    safe_umount "${ESP_FS_DIR}"
    sudo syslinux -d /syslinux "${ESP_DEV}"
    # mount again for cleanup to free resource gracefully
    sudo mount -o ro "${ESP_DEV}" "${ESP_FS_DIR}"
  fi
elif [[ "${FLAGS_arch}" == "arm" || "${FLAGS_arch}" == "mips" ]]; then
  # Copy u-boot script to ESP partition
  if [ -r "${FLAGS_from}/boot-A.scr.uimg" ]; then
    sudo mkdir -p "${ESP_FS_DIR}/u-boot"
    sudo cp "${FLAGS_from}/boot-A.scr.uimg" \
      "${ESP_FS_DIR}/u-boot/boot.scr.uimg"
    sudo cp -f "${FLAGS_vmlinuz}" "${ESP_FS_DIR}"/vmlinuz.A
    if [ -r "${FLAGS_zimage}" ]; then
      sudo cp -f "${FLAGS_zimage}" "${ESP_FS_DIR}"/vmlinuz.A
    fi
  fi
fi

set +e
