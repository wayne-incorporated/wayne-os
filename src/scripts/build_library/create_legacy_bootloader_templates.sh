#!/bin/bash

# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Helper script to generate GRUB bootloader configuration files for
# x86 platforms.

SCRIPT_ROOT=$(readlink -f "$(dirname "$0")"/..)
# shellcheck source=../common.sh
. "${SCRIPT_ROOT}/common.sh" || exit 1
# shellcheck source=disk_layout_util.sh
. "${BUILD_LIBRARY_DIR}/disk_layout_util.sh" || exit 1

# We're invoked only by build_image, which runs in the chroot
assert_inside_chroot

# Flags.
DEFINE_string arch "x86" \
  "The boot architecture: arm or x86. (Default: x86)"
DEFINE_string board "" \
  "Board we're building for."
DEFINE_string to "/tmp/boot" \
  "Path to populate with bootloader templates (Default: /tmp/boot)"
DEFINE_string boot_args "" \
  "Additional boot arguments to pass to the commandline (Default: '')"
DEFINE_boolean enable_rootfs_verification "${FLAGS_FALSE}" \
  "Controls if verity is used for root filesystem checking (Default: false)"
DEFINE_string enable_serial "tty2" \
  "Enable serial port for printks. Example values: ttyS0 (Default: tty2)"
DEFINE_string image_type "usb" \
  "Type of image we're building for."
DEFINE_integer loglevel 7 \
  "The loglevel to add to the kernel command line."
DEFINE_integer verity_error_behavior 3 \
  "Verified boot error behavior [0: I/O errors, 1: reboot, 2: nothing] \
(Default: 3)"
DEFINE_integer verity_max_ios -1 \
  "Optional number of outstanding I/O operations. (Default: 1024)"

# Parse flags
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"
switch_to_strict_mode

# Only let dm-verity block if rootfs verification is configured.
# Also, set which device mapper correspondes to verity
dev_wait=0
ROOTDEV=/dev/dm-0
if [[ ${FLAGS_enable_rootfs_verification} -eq ${FLAGS_TRUE} ]]; then
  dev_wait=1
fi

# Common kernel command-line args. Write them to a temporary config_file so that
# boards can modify them if needed.
# TODO: This code to support modifying kernel command line by boards is very
# similar to the one in build_kernel_image.sh. This could be refactored into a
# common place. Until then it needs to be kept consistent.
config_file="$(mktemp --tmpdir legacy_config_XXXXXXXXXX.txt)"
cleanup() {
  rm -f "${config_file}"
}
trap cleanup EXIT

cat <<EOF > "${config_file}"
init=/sbin/init
rootwait
ro
noresume
loglevel=${FLAGS_loglevel}
${FLAGS_boot_args}
console=${FLAGS_enable_serial}
EOF

# Support optional, board-specific kernel parameters.

# Intended to be overridden by boards that wish to add to the command
# line. Same code in build_kernel_image.sh; this one here is for grub
# and syslinux.
# $1 - output file containing boot args.
modify_kernel_command_line() {
  :
}

# shellcheck source=board_options.sh
. "${BUILD_LIBRARY_DIR}/board_options.sh" || exit 1
(
  # Run in a subshell so we know build_kernel_image.sh can't set env vars.
  load_board_specific_script "build_kernel_image.sh"
  modify_kernel_command_line "${config_file}"
)
# Read back the config_file; translate newlines to space
common_args="$(tr "\n" " " < "${config_file}")"
cleanup
trap - EXIT

# Common verified boot command-line args
verity_common="dm_verity.error_behavior=${FLAGS_verity_error_behavior}"
verity_common="${verity_common} dm_verity.max_bios=${FLAGS_verity_max_ios}"
# Ensure that dm-verity waits for its device.
# TODO(wad) should add a timeout that display a useful message
verity_common="${verity_common} dm_verity.dev_wait=${dev_wait}"

# Discover last known partition numbers.
partition_num_kern_a="$(get_layout_partition_number \
    "${FLAGS_image_type}" KERN-A)"
partition_num_kern_b="$(get_layout_partition_number \
    "${FLAGS_image_type}" KERN-B)"
partition_num_root_a="$(get_layout_partition_number \
    "${FLAGS_image_type}" ROOT-A)"

# Create grub image and common grub.cfg template for EFI on x86/amd64/arm64.
install_grub_efi_template() {
  # To cover all of our bases, now populate templated boot support for efi.
  sudo mkdir -p "${FLAGS_to}"/efi/boot

  # /boot/syslinux must be installed in partition 12 as /syslinux/.
  SYSLINUX_DIR="${FLAGS_to}/syslinux"
  sudo mkdir -p "${SYSLINUX_DIR}"

  grub_args=(
    -p /efi/boot
    part_gpt gptpriority test fat ext2 normal boot chain
    efi_gop configfile linux
    # For more context on SBAT, see chromiumos-overlay/sys-boot/grub/README.md
    -s "${SRC_ROOT}/third_party/chromiumos-overlay/sys-boot/grub/files/sbat.csv"
  )

  if [[ "${FLAGS_arch}" == "arm64" ]]; then
    # GRUB for arm64 is installed inside board overlay, since cross compilation
    # tools are not available in base SDK.
    sudo grub-mkimage -O arm64-efi \
      -d "/build/${FLAGS_board}/lib64/grub/arm64-efi/" \
      -o "${FLAGS_to}/efi/boot/bootaa64.efi" "${grub_args[@]}"
  else
    sudo grub-mkimage -O x86_64-efi \
      -o "${FLAGS_to}/efi/boot/bootx64.efi" "${grub_args[@]}"
    sudo grub-mkimage -O i386-efi \
      -o "${FLAGS_to}/efi/boot/bootia32.efi" "${grub_args[@]}"
  fi

  # Templated variables:
  #  DMTABLEA, DMTABLEB -> '0 xxxx verity ... '
  # This should be replaced during postinst when updating the ESP.
  cat <<EOF | sudo dd of="${FLAGS_to}/efi/boot/grub.cfg" 2>/dev/null
defaultA=0
defaultB=1
gptpriority \$grubdisk ${partition_num_kern_a} prioA
gptpriority \$grubdisk ${partition_num_kern_b} prioB

if [ \$prioA -lt \$prioB ]; then
  set default=\$defaultB
else
  set default=\$defaultA
fi

# Modified by seongbin@wayne-inc.com
# set timeout=2
set timeout=0

# NOTE: These magic grub variables are a Chrome OS hack. They are not portable.

menuentry "local image A" {
  linux /syslinux/vmlinuz.A ${common_args} i915.modeset=1 cros_efi \
      root=/dev/\$linuxpartA
}

menuentry "local image B" {
  linux /syslinux/vmlinuz.B ${common_args} i915.modeset=1 cros_efi \
      root=/dev/\$linuxpartB
}

menuentry "verified image A" {
  linux /syslinux/vmlinuz.A ${common_args} ${verity_common} \
      i915.modeset=1 cros_efi root=${ROOTDEV} dm="DMTABLEA"
}

menuentry "verified image B" {
  linux /syslinux/vmlinuz.B ${common_args} ${verity_common} \
      i915.modeset=1 cros_efi root=${ROOTDEV} dm="DMTABLEB"
}

# FIXME: usb doesn't support verified boot for now
menuentry "Alternate USB Boot" {
  linux (hd0,${partition_num_root_a})/boot/vmlinuz ${common_args} root=HDROOTUSB i915.modeset=1 cros_efi
}
EOF
  if [[ ${FLAGS_enable_rootfs_verification} -eq ${FLAGS_TRUE} ]]; then
    sudo sed -i \
      -e '/^defaultA=/s:=.*:=2:' \
      -e '/^defaultB=/s:=.*:=3:' \
      "${FLAGS_to}/efi/boot/grub.cfg"
  fi
  info "Emitted ${FLAGS_to}/efi/boot/grub.cfg"
}

# Populate the x86 rootfs to support legacy and EFI bios config templates.
# The templates are used by the installer to populate partition 12 with
# the correct bootloader configuration.
if [[ "${FLAGS_arch}" == "x86" || "${FLAGS_arch}" == "amd64"  ]]; then
  # TODO: For some reason the /dev/disk/by-uuid is not being generated by udev
  # in the initramfs. When we figure that out, switch to root=UUID=${UUID}.
  sudo mkdir -p "${FLAGS_to}"

  # /boot/syslinux must be installed in partition 12 as /syslinux/.
  SYSLINUX_DIR="${FLAGS_to}/syslinux"
  sudo mkdir -p "${SYSLINUX_DIR}"

  cat <<EOF | sudo dd of="${SYSLINUX_DIR}/syslinux.cfg" 2>/dev/null
PROMPT 0
TIMEOUT 0

# the actual target
include /syslinux/default.cfg

# chromeos-usb.A
include /syslinux/usb.A.cfg

# chromeos-hd.A / chromeos-vhd.A
include /syslinux/root.A.cfg

# chromeos-hd.B / chromeos-vhd.B
include /syslinux/root.B.cfg
EOF
  info "Emitted ${SYSLINUX_DIR}/syslinux.cfg"

  if [[ ${FLAGS_enable_rootfs_verification} -eq ${FLAGS_TRUE} ]]; then
    # To change the active target, only this file needs to change.
    cat <<EOF | sudo dd of="${SYSLINUX_DIR}/default.cfg" 2>/dev/null
DEFAULT chromeos-vusb.A
EOF
  else
    # To change the active target, only this file needs to change.
    cat <<EOF | sudo dd of="${SYSLINUX_DIR}/default.cfg" 2>/dev/null
DEFAULT chromeos-usb.A
EOF
  fi
  info "Emitted ${SYSLINUX_DIR}/default.cfg"

  cat <<EOF | sudo dd of="${SYSLINUX_DIR}/usb.A.cfg" 2>/dev/null
label chromeos-usb.A
  menu label chromeos-usb.A
  kernel vmlinuz.A
  append ${common_args} root=HDROOTUSB i915.modeset=1 cros_legacy

label chromeos-vusb.A
  menu label chromeos-vusb.A
  kernel vmlinuz.A
  append ${common_args} ${verity_common} root=${ROOTDEV} \
      i915.modeset=1 cros_legacy dm="DMTABLEA"
EOF
  info "Emitted ${SYSLINUX_DIR}/usb.A.cfg"

  # Different files are used so that the updater can only touch the file it
  # needs to for a given change.  This will minimize any potential accidental
  # updates issues, hopefully.
  cat <<EOF | sudo dd of="${SYSLINUX_DIR}/root.A.cfg" 2>/dev/null
label chromeos-hd.A
  menu label chromeos-hd.A
  kernel vmlinuz.A
  append ${common_args} root=HDROOTA i915.modeset=1 cros_legacy

label chromeos-vhd.A
  menu label chromeos-vhd.A
  kernel vmlinuz.A
  append ${common_args} ${verity_common} root=${ROOTDEV} \
      i915.modeset=1 cros_legacy dm="DMTABLEA"
EOF
  info "Emitted ${SYSLINUX_DIR}/root.A.cfg"

  cat <<EOF | sudo dd of="${SYSLINUX_DIR}/root.B.cfg" 2>/dev/null
label chromeos-hd.B
  menu label chromeos-hd.B
  kernel vmlinuz.B
  append ${common_args} root=HDROOTB i915.modeset=1 cros_legacy

label chromeos-vhd.B
  menu label chromeos-vhd.B
  kernel vmlinuz.B
  append ${common_args} ${verity_common} root=${ROOTDEV} \
      i915.modeset=1 cros_legacy dm="DMTABLEB"
EOF
  info "Emitted ${SYSLINUX_DIR}/root.B.cfg"

  cat <<EOF | sudo dd of="${SYSLINUX_DIR}/README" 2>/dev/null
Partition 12 contains the active bootloader configuration when
booting from a non-Chrome OS BIOS.  EFI BIOSes use /efi/*
and legacy BIOSes use this syslinux configuration.
EOF
  info "Emitted ${SYSLINUX_DIR}/README"

  install_grub_efi_template
  exit 0
elif [[ "${FLAGS_arch}" == "arm64" ]] && \
     [[ -d "/build/${FLAGS_board}/lib64/grub/arm64-efi/" ]]; then
  install_grub_efi_template
  exit 0
fi

info "The target platform does not use bootloader templates."
