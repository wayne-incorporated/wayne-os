#!/bin/bash

# Copyright (c) 2009-2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to update the kernel on a live running ChromiumOS instance.

SCRIPT_ROOT=$(dirname $(readlink -f "$0"))
. "${SCRIPT_ROOT}/common.sh" || exit 1
. "${SCRIPT_ROOT}/remote_access.sh" || exit 1

# Script must be run inside the chroot.
restart_in_chroot_if_needed "$@"

DEFINE_string board "" "Override board reported by target"
DEFINE_string device "" "Override boot device reported by target"
DEFINE_string partition "" "Override kernel partition reported by target"
DEFINE_string rootoff "" "Override root offset"
DEFINE_string rootfs "" "Override rootfs partition reported by target"
DEFINE_string arch "" "Override architecture reported by target"
DEFINE_boolean clean $FLAGS_FALSE "Remove old files before sending new files"
DEFINE_boolean hv $FLAGS_TRUE "Use hypervisor kernel if available."
DEFINE_boolean ignore_verity $FLAGS_FALSE "Update kernel even if system is using verity \
(WARNING: likely to make the system unable to boot)"
DEFINE_boolean reboot $FLAGS_TRUE "Reboot system after update"
DEFINE_boolean vboot $FLAGS_TRUE "Update the vboot kernel"
DEFINE_boolean syslinux $FLAGS_TRUE "Update the syslinux kernel (including /boot)"
DEFINE_boolean bootonce $FLAGS_FALSE "Mark kernel partition as boot once"
DEFINE_boolean remote_bootargs $FLAGS_FALSE "Use bootargs from running kernel on target"
DEFINE_boolean firmware $FLAGS_FALSE "Also update firmwares (/lib/firmware)"
DEFINE_boolean ab_update $FLAGS_FALSE "Update the kernel in the non-booting \
kernel slot, similar to an AB update"
DEFINE_string boot_command "" "Command to run on remote after update (after reboot if applicable)"

ORIG_ARGS=("$@")

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Only now can we die on error.  shflags functions leak non-zero error codes,
# so will die prematurely if 'switch_to_strict_mode' is specified before now.
switch_to_strict_mode

cleanup() {
  cleanup_remote_access
  rm -rf "${TMP}"
}

# If rsync errors due to no space on the device, suggest running with the clean
# flag to make space before copying
handle_no_space() {
  if [[ ${FLAGS_clean} -ne ${FLAGS_TRUE} ]]; then
    warn "There is not enough space to copy all necessary files."
    warn "Try running again with the --clean flag."
  fi
  die_notrace "No space left on device."
}

learn_device() {
  [ -n "${FLAGS_device}" ] && return
  remote_sh rootdev -s
  # shellcheck disable=SC2001
  FLAGS_device=$(echo "${REMOTE_OUT}" | sed -E 's/[0-9]+$//')
  info "Target reports root device is ${FLAGS_device}"
}

# Delete the fixed numbers after R65 when we don't care about <R57 upgrades.
load_default_partition_numbers() {
  PARTITION_NUM_KERN_A=2
  PARTITION_NUM_ROOT_A=3
  PARTITION_NUM_KERN_B=4
  PARTITION_NUM_ROOT_B=5
  PARTITION_NUM_EFI_SYSTEM=12
}

# Ask the target what the kernel partition is
learn_partition_and_ro() {
  ! remote_sh rootdev
  if [ "${REMOTE_OUT%%-*}" == "/dev/dm" ]; then
    remote_sh rootdev -s
    REMOTE_VERITY=${FLAGS_TRUE}
    if [[ ${FLAGS_ignore_verity} -eq ${FLAGS_TRUE} ]]; then
        warn "System is using verity: not updating firmware/modules"
    else
        warn "System is using verity: First remove rootfs verification using"
        warn "/usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification"
        warn "on the DUT."
        die_notrace
    fi
  else
    REMOTE_VERITY=${FLAGS_FALSE}
    info "System is not using verity: updating firmware and modules"
  fi
  if [[ ${FLAGS_ab_update} -eq ${FLAGS_TRUE} ]]; then
    if [[ "${REMOTE_OUT}" == "${FLAGS_device}${PARTITION_NUM_ROOT_A}" ]]; then
      FLAGS_partition="${FLAGS_device}${PARTITION_NUM_KERN_B}"
      FLAGS_rootfs="${FLAGS_device}${PARTITION_NUM_ROOT_B}"
    else
      FLAGS_partition="${FLAGS_device}${PARTITION_NUM_KERN_A}"
      FLAGS_rootfs="${FLAGS_device}${PARTITION_NUM_ROOT_A}"
    fi
  fi
  if [[ -z "${FLAGS_rootfs}" ]]; then
    FLAGS_rootfs="${REMOTE_OUT}"
  fi
  # If rootfs is for different partition than we're currently running on
  # mount it manually to update the right modules, firmware, etc.
  REMOTE_NEEDS_ROOTFS_MOUNTED=${FLAGS_FALSE}
  if [[ "${REMOTE_OUT}" != "${FLAGS_rootfs}" ]]; then
    REMOTE_NEEDS_ROOTFS_MOUNTED=${FLAGS_TRUE}
  fi
  [ -n "${FLAGS_partition}" ] && return
  if [ "${REMOTE_OUT}" == "${FLAGS_device}${PARTITION_NUM_ROOT_A}" ]; then
    FLAGS_partition="${FLAGS_device}${PARTITION_NUM_KERN_A}"
  else
    FLAGS_partition="${FLAGS_device}${PARTITION_NUM_KERN_B}"
  fi
  if [ -z "${FLAGS_partition}" ]; then
    die_notrace "Partition required"
  fi
  if [ ${REMOTE_VERITY} -eq ${FLAGS_TRUE} ]; then
    info "Target reports kernel partition is ${FLAGS_partition}"
    if [ ${FLAGS_vboot} -eq ${FLAGS_FALSE} ]; then
      die_notrace "Must update vboot when target is using verity"
    fi
  fi
}

get_bootargs() {
  local local_config="${SRC_ROOT}/build/images/${FLAGS_board}/latest/config.txt"

  # Autodetect by default.  https://crbug.com/316239
  # This isn't quite right if people use --noremote_bootargs, but that's not
  # a scenario people do today, so we won't worry about it.
  if [[ ${FLAGS_remote_bootargs} -eq ${FLAGS_FALSE} && \
        ! -e "${local_config}" ]]; then
    warn "Local kernel config does not exist: ${local_config}"
    FLAGS_remote_bootargs=${FLAGS_TRUE}
  fi

  if [ ${FLAGS_remote_bootargs} -eq ${FLAGS_TRUE} ] ; then
    info "Using remote bootargs"
    remote_sh dump_kernel_config "${FLAGS_partition}"
    printf '%s' "${REMOTE_OUT}"
  else
    if [ -n "${FLAGS_rootoff}" ]; then
      sed "s/PARTNROFF=1/PARTNROFF=${FLAGS_rootoff}/" "${local_config}"
    else
      cat "${local_config}"
    fi
  fi
}

learn_arch() {
  [ -n "${FLAGS_arch}" ] && return
  FLAGS_arch=$(sed -n -E 's/^CONFIG_(ARM|ARM64|X86)=y/\1/p' \
               /build/"${FLAGS_board}"/boot/config-* | \
               uniq | awk '{print tolower($0)}')
  if [ -z "${FLAGS_arch}" ]; then
    error "Arch required"
    exit 1
  fi
  info "Target reports arch is ${FLAGS_arch}"
}

make_kernelimage() {
  local bootloader_path
  local kernel_image
  local boot_path="/build/${FLAGS_board}"
  local config_path="$(mktemp /tmp/config.txt.XXXXX)"
  if [[ ${FLAGS_hv} -eq ${FLAGS_TRUE} && \
        -d "${boot_path}/build/manatee/boot" ]]; then
    boot_path+="/build/manatee/boot"
  else
    boot_path+="/boot"
  fi
  kernel_image="${boot_path}/vmlinuz"
  if [[ "${FLAGS_arch}" == "arm" || "${FLAGS_arch}" == "arm64" ]]; then
    name="bootloader.bin"
    bootloader_path="${SRC_ROOT}/build/images/${FLAGS_board}/latest/${name}"
    # If there is no local bootloader stub, create a dummy file.  This matches
    # build_kernel_image.sh.  If we wanted to be super paranoid, we could copy
    # and extract it from the remote image, if it had one.
    if [[ ! -e "${bootloader_path}" ]]; then
      warn "Bootloader does not exist; creating a stub"
      bootloader_path="${TMP}/${name}"
      truncate -s 512 "${bootloader_path}"
    fi
  else
    bootloader_path="/lib64/bootstub/bootstub.efi"
  fi
  get_bootargs > "${config_path}"
  vbutil_kernel --pack $TMP/new_kern.bin \
    --keyblock /usr/share/vboot/devkeys/kernel.keyblock \
    --signprivate /usr/share/vboot/devkeys/kernel_data_key.vbprivk \
    --version 1 \
    --config ${config_path} \
    --bootloader "${bootloader_path}" \
    --vmlinuz "${kernel_image}" \
    --arch "${FLAGS_arch}"
  rm "${config_path}"
}

copy_kernelmodules() {
  local basedir="$1" # rootfs directory (could be in /tmp) or empty string
  local modules_dir=/build/"${FLAGS_board}"/lib/modules/
  if [ ! -d "${modules_dir}" ]; then
    info "No modules. Skipping."
    return
  fi
  if [[ ${FLAGS_clean} -eq ${FLAGS_TRUE} ]]; then
    info "Cleaning /lib/modules"
    remote_sh rm -rf "${basedir}/lib/modules/*"
  fi
  info "Copying modules"
  remote_send_to "${modules_dir}" "${basedir}"/lib/modules
}

copy_kernelimage() {
  remote_sh dd of="${FLAGS_partition}" bs=4K < "${TMP}/new_kern.bin"
}

check_kernelbuildtime() {
  local version=$(readlink "/build/${FLAGS_board}/boot/vmlinuz" | cut -d- -f2-)
  local build_dir="/build/${FLAGS_board}/lib/modules/${version}/build"
  if [ "${build_dir}/Makefile" -nt "/build/${FLAGS_board}/boot/vmlinuz" ]; then
    warn "Your build directory has been built more recently than"
    warn "the installed kernel being updated to.  Did you forget to"
    warn "run 'cros_workon_make chromeos-kernel --install'?"
  fi
}

mark_boot_once() {
  local idx=${FLAGS_partition##*[^0-9]}
  remote_sh cgpt add -i ${idx} -S 0 -T 1 -P 15 ${FLAGS_device%p}
}

update_syslinux_kernel() {
  local basedir="$1" # rootfs directory (could be in /tmp) or empty string
  # ARM does not have the syslinux directory, so skip it when the
  # partition is missing, the file system fails to mount, or the syslinux
  # vmlinuz target is missing.
  remote_sh grep $(echo ${FLAGS_device}${PARTITION_NUM_EFI_SYSTEM} | cut -d/ -f3) /proc/partitions
  if [ $(echo "$REMOTE_OUT" | wc -l) -eq 1 ]; then
    remote_sh mkdir -p /tmp/${PARTITION_NUM_EFI_SYSTEM}
    if remote_sh mount ${FLAGS_device}${PARTITION_NUM_EFI_SYSTEM} \
                       /tmp/${PARTITION_NUM_EFI_SYSTEM}; then

      if [ "$FLAGS_partition" = "${FLAGS_device}${PARTITION_NUM_KERN_A}" ]; then
        target="/tmp/${PARTITION_NUM_EFI_SYSTEM}/syslinux/vmlinuz.A"
      else
        target="/tmp/${PARTITION_NUM_EFI_SYSTEM}/syslinux/vmlinuz.B"
      fi
      remote_sh "test ! -f ${target} || \
                 cp ${basedir}/boot/vmlinuz ${target}"

      remote_sh umount /tmp/${PARTITION_NUM_EFI_SYSTEM}
    fi
    remote_sh rmdir /tmp/${PARTITION_NUM_EFI_SYSTEM}
  fi
}

multi_main() {
  local host

  IFS=","
  for host in ${FLAGS_remote}; do
    "$0" "${ORIG_ARGS[@]}" --remote="${host}" \
      |& sed "s/^/${V_BOLD_YELLOW}${host}: ${V_VIDOFF}/" &
  done
  wait
}

main() {
  # If there are commas in the --remote, run the script in parallel.
  if [[ ${FLAGS_remote} == *,* ]]; then
    multi_main
    return $?
  fi

  trap cleanup EXIT

  TMP=$(mktemp -d /tmp/update_kernel.XXXXXX)

  remote_access_init

  learn_board

  learn_arch

  learn_device

  learn_partition_layout
  if [[ -z "${PARTITION_NUM_KERN_A}" ]]; then
    info "Target has no partition number info, use default instead"
    load_default_partition_numbers
  fi

  learn_partition_and_ro

  if ! remote_sh "test -e '${FLAGS_partition}'"; then
    die_notrace "Could not find kernel partition on DUT; path='${FLAGS_partition}'"
  fi

  remote_sh uname -r -v

  old_kernel="${REMOTE_OUT}"

  check_kernelbuildtime

  if [ ${FLAGS_vboot} -eq ${FLAGS_TRUE} ]; then
    make_kernelimage
  fi

  if [[ ${REMOTE_VERITY} -eq ${FLAGS_FALSE} ]]; then
    local remote_basedir
    if [[ ${REMOTE_NEEDS_ROOTFS_MOUNTED} -eq ${FLAGS_TRUE} ]]; then
      remote_sh mktemp -d /tmp/rootfs_mounted.XXXXXX
      remote_basedir="${REMOTE_OUT}"
      remote_sh mount "${FLAGS_rootfs}" "${remote_basedir}"
    else
      remote_sh mount -o remount,rw /
    fi

    if [[ ${FLAGS_syslinux} -eq ${FLAGS_TRUE} ]]; then
      if [[ ${FLAGS_clean} -eq ${FLAGS_TRUE} ]]; then
        info "Cleaning /boot"
        remote_sh rm -rf "${remote_basedir}"/boot/{System,config,vmlinuz}'*'
      fi
      info "Copying syslinux and /boot"
      remote_send_to /build/"${FLAGS_board}"/boot/ "${remote_basedir}"/boot/
      update_syslinux_kernel "${remote_basedir}"
    else
      info "Skipping syslinux and /boot (per request)"
    fi

    copy_kernelmodules "${remote_basedir}"

    if [[ ${FLAGS_firmware} -eq ${FLAGS_TRUE} ]]; then
      if [[ ${FLAGS_clean} -eq ${FLAGS_TRUE} ]]; then
        info "Cleaning /lib/firmware"
        remote_sh rm -rf "${remote_basedir}/lib/firmware/*"
      fi
      info "Copying firmware (per request)"
      remote_send_to /build/"${FLAGS_board}"/lib/firmware/ \
                     "${remote_basedir}"/lib/firmware/
    fi
    if [[ ${REMOTE_NEEDS_ROOTFS_MOUNTED} -eq ${FLAGS_TRUE} ]]; then
      remote_sh umount "${remote_basedir}"
      remote_sh rmdir "${remote_basedir}"
    fi
  fi

  if [ ${FLAGS_vboot} -eq ${FLAGS_TRUE} ]; then
    info "Copying vboot kernel image"
    copy_kernelimage
  else
    info "Skipping update of vboot (per request)"
  fi

  if [ ${FLAGS_bootonce} -eq ${FLAGS_TRUE} ]; then
    info "Marking kernel partition ${FLAGS_partition} as boot once"
    mark_boot_once
  fi

  # An early kernel panic can prevent the normal sync on reboot.  Explicitly
  # sync for safety to avoid random file system corruption.
  remote_sh sync

  if [ ${FLAGS_reboot} -eq ${FLAGS_TRUE} ]; then
    remote_reboot

    remote_sh uname -r -v
    info "old kernel: ${old_kernel}"
    info "new kernel: ${REMOTE_OUT}"
  else
    info "Not rebooting (per request)"
  fi

  if [ -n "${FLAGS_boot_command}" ]; then
    info "Running boot command on remote"
    remote_sh "${FLAGS_boot_command}"
  fi
}

main "$@"
