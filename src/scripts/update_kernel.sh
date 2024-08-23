#!/bin/bash

# Copyright 2009-2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to update the kernel on a live running ChromiumOS instance.

SCRIPT_ROOT="$(dirname "$(readlink -f "$0")")"
# shellcheck source=common.sh
. "${SCRIPT_ROOT}/common.sh" || exit 1
# shellcheck source=remote_access.sh
. "${SCRIPT_ROOT}/remote_access.sh" || exit 1

# Script must be run inside the chroot.
restart_in_chroot_if_needed "$@"

FLAGS_HELP="usage: $(basename "$0") [flags]

Updates the kernel on a target CrOS system. Supports both real hardware and
QEMU VMs (e.g., betty/amd64-generic with 'cros_vm'). Note that there are some
assumptions about the CrOS verified boot chain, so command-line updates may not
work well on non-vboot systems (such as BIOS or EFI boot on QEMU).
"

DEFINE_string board "" "Override board reported by target"
DEFINE_string device "" "Override boot device reported by target"
DEFINE_string partition "" "Override kernel partition reported by target"
DEFINE_string rootoff "" "Override root offset"
DEFINE_string rootfs "" "Override rootfs partition reported by target"
DEFINE_string arch "" "Override architecture reported by target"
DEFINE_boolean clean "${FLAGS_TRUE}" "Remove old files before sending new files"
DEFINE_boolean ignore_verity "${FLAGS_FALSE}" "Update kernel even if system \
is using verity (WARNING: likely to make the system unable to boot)"
DEFINE_boolean reboot "${FLAGS_TRUE}" "Reboot system after update"
DEFINE_boolean vboot "${FLAGS_TRUE}" "Update the vboot kernel"
DEFINE_boolean vmlinux "${FLAGS_FALSE}" "Update the vmlinux.debug symbol"
DEFINE_boolean syslinux "${FLAGS_TRUE}" \
  "Update the syslinux kernel (including /boot)"
DEFINE_boolean bootonce "${FLAGS_FALSE}" "Mark kernel partition as boot once"
DEFINE_boolean remote_bootargs "${FLAGS_FALSE}" \
  "Use bootargs from running kernel on target"
DEFINE_boolean firmware "${FLAGS_FALSE}" "Also update firmwares (/lib/firmware)"
DEFINE_boolean ab_update "${FLAGS_FALSE}" \
  "Update the kernel in the non-booting kernel slot, similar to an AB update"
DEFINE_string boot_command "" \
  "Command to run on remote after update (after reboot if applicable)"

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

# Ask the target what the kernel partition is
learn_partition_and_ro() {
  remote_sh rootdev -s || die_notrace
  if [[ "${FLAGS_ab_update}" -eq "${FLAGS_TRUE}" ]]; then
    if [[ "${REMOTE_OUT}" == "${FLAGS_device}${PARTITION_NUM_ROOT_A}" ]]; then
      FLAGS_partition="${FLAGS_device}${PARTITION_NUM_KERN_B}"
      FLAGS_rootfs="${FLAGS_device}${PARTITION_NUM_ROOT_B}"
    else
      FLAGS_partition="${FLAGS_device}${PARTITION_NUM_KERN_A}"
      FLAGS_rootfs="${FLAGS_device}${PARTITION_NUM_ROOT_A}"
    fi
  else
    if [[ -z "${FLAGS_rootfs}" ]]; then
      FLAGS_rootfs="${REMOTE_OUT}"
    fi

    if [[ -z "${FLAGS_partition}" ]]; then
      if [ "${REMOTE_OUT}" == "${FLAGS_device}${PARTITION_NUM_ROOT_A}" ]; then
        FLAGS_partition="${FLAGS_device}${PARTITION_NUM_KERN_A}"
      else
        FLAGS_partition="${FLAGS_device}${PARTITION_NUM_KERN_B}"
      fi
    fi
  fi

  # If rootfs is for different partition than we're currently running on
  # mount it manually to update the right modules, firmware, etc.
  REMOTE_NEEDS_ROOTFS_MOUNTED=${FLAGS_FALSE}
  if [[ "${REMOTE_OUT}" != "${FLAGS_rootfs}" ]]; then
    REMOTE_NEEDS_ROOTFS_MOUNTED=${FLAGS_TRUE}
  fi

  # Check if the partition has removed rootfs verification
  remote_sh dump_kernel_config "${FLAGS_partition}"
  if [[ "${REMOTE_OUT}" =~ root=/dev/dm-[0-9] ]]; then
    REMOTE_VERITY=${FLAGS_TRUE}
    if [[ "${FLAGS_ignore_verity}" -eq "${FLAGS_TRUE}" ]]; then
        warn "System is using verity: not updating firmware/modules"
    else
        warn "System is using verity: First remove rootfs verification using"
        warn "/usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions ${FLAGS_partition: -1}"
        warn "on the DUT."
        die_notrace
    fi
  else
    REMOTE_VERITY=${FLAGS_FALSE}
    info "System is not using verity: updating firmware and modules"
  fi

  if [[ "${REMOTE_VERITY}" -eq "${FLAGS_TRUE}" ]]; then
    info "Target reports kernel partition is ${FLAGS_partition}"
    if [[ "${FLAGS_vboot}" -eq "${FLAGS_FALSE}" ]]; then
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

  if [[ "${FLAGS_remote_bootargs}" -eq "${FLAGS_TRUE}" ]]; then
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
  local kernel_image
  local boot_path="/build/${FLAGS_board}/boot"
  local config_path
  config_path="$(mktemp /tmp/config.txt.XXXXX)"
  kernel_image="${boot_path}/vmlinuz"
  get_bootargs > "${config_path}"
  vbutil_kernel --pack "${TMP}"/new_kern.bin \
    --keyblock /usr/share/vboot/devkeys/kernel.keyblock \
    --signprivate /usr/share/vboot/devkeys/kernel_data_key.vbprivk \
    --version 1 \
    --config "${config_path}" \
    --vmlinuz "${kernel_image}" \
    --arch "${FLAGS_arch}"
  rm "${config_path}"
}

check_buildid() {
  local vmlinux="/build/${FLAGS_board}/usr/lib/debug/boot/vmlinux"
  if [[ ! -f "${vmlinux}" ]]; then
    warn "Can't find vmlinux. Skipping buildid check."
    return
  fi

  llvm-objcopy -j.notes "${vmlinux}" -O binary "${TMP}/new_kern.notes"
  if [[ ! -f "${TMP}/new_kern.notes" ]]; then
    warn "Can't parse notes from vmlinux. Skipping buildid check."
    return
  fi
  echo "/sys/kernel/notes" >> "${TMP}/copy_notes"
  remote_rsync_from "${TMP}/copy_notes" "${TMP}/remote_kern.notes"
  if [[ ! -f "${TMP}/remote_kern.notes" ]]; then
    warn "Can't read notes from remote. Skipping buildid check."
    return
  fi

  cmp "${TMP}/new_kern.notes" "${TMP}/remote_kern.notes" >/dev/null ||
  error "BuildID differs. Update kernel failed."
}

copy_kernelmodules() {
  local basedir="$1" # rootfs directory (could be in /tmp) or empty string
  local old_kern_ver="$2"
  local new_kern_ver="$3"
  local modules_dir=/build/"${FLAGS_board}"/lib/modules/
  if [ ! -d "${modules_dir}" ]; then
    info "No modules. Skipping."
    return
  fi
  if [[ ${FLAGS_clean} -eq ${FLAGS_TRUE} ]]; then
    info "Cleaning and copying modules"
    if [[ "${old_kern_ver}" != "${new_kern_ver}" ]]; then
      remote_sh mv "${basedir}/lib/modules/${old_kern_ver}" \
        "${basedir}/lib/modules/${new_kern_ver}" || true
    fi
    remote_send_to "${modules_dir}" "${basedir}"/lib/modules --delete
  else
    info "Copying modules"
    remote_send_to "${modules_dir}" "${basedir}"/lib/modules
  fi
}

copy_kernelimage() {
  remote_sh dd of="${FLAGS_partition}" bs=4K < "${TMP}/new_kern.bin"
}

copy_vmlinux() {
  local symbol_dir="/usr/lib/debug/boot"
  local symbol="/build/${FLAGS_board}/${symbol_dir}/vmlinux.debug"
  if [[ ! -f "${symbol}" ]]; then
    warn "Can't find vmlinux.debug. Skipping update vmlinux.debug."
    return
  fi

  remote_sh mkdir -p "${symbol_dir}"
  remote_cp_to "${symbol}" "${symbol_dir}"/vmlinux.debug
}

check_kernelbuildtime() {
  local version="$1"
  local build_dir
  build_dir="/build/${FLAGS_board}/lib/modules/${version}/build"
  if [ "${build_dir}/Makefile" -nt "/build/${FLAGS_board}/boot/vmlinuz" ]; then
    warn "Your build directory has been built more recently than"
    warn "the installed kernel being updated to.  Did you forget to"
    warn "run 'cros_workon_make chromeos-kernel --install'?"
  fi
}

mark_boot_once() {
  local idx=${FLAGS_partition##*[^0-9]}
  remote_sh cgpt add -i "${idx}" -S 0 -T 1 -P 15 "${FLAGS_device%p}"
}

update_syslinux_kernel() {
  local basedir="$1" # rootfs directory (could be in /tmp) or empty string

  # All systems _should_ have the EFI variables defined, but we already make
  # syslinux updates optional, so make this optional too.
  if [[ -z "${PARTITION_NUM_EFI_SYSTEM}" ]]; then
    warn "Target is missing EFI partition info; skipping syslinux"
    return
  fi

  # ARM does not have the syslinux directory, so skip it when the
  # partition is missing, the file system fails to mount, or the syslinux
  # vmlinuz target is missing.
  remote_sh grep \
    "$(echo "${FLAGS_device}${PARTITION_NUM_EFI_SYSTEM}" | cut -d/ -f3)" \
    /proc/partitions
  if [[ "$(echo "${REMOTE_OUT}" | wc -l)" -eq 1 ]]; then
    remote_sh mkdir -p "/tmp/${PARTITION_NUM_EFI_SYSTEM}"
    if remote_sh mount "${FLAGS_device}${PARTITION_NUM_EFI_SYSTEM}" \
                       "/tmp/${PARTITION_NUM_EFI_SYSTEM}"; then

      if [[ "${FLAGS_partition}" = \
            "${FLAGS_device}${PARTITION_NUM_KERN_A}" ]]; then
        target="/tmp/${PARTITION_NUM_EFI_SYSTEM}/syslinux/vmlinuz.A"
      else
        target="/tmp/${PARTITION_NUM_EFI_SYSTEM}/syslinux/vmlinuz.B"
      fi
      remote_sh "test ! -f ${target} || \
                 cp ${basedir}/boot/vmlinuz ${target}"

      remote_sh umount "/tmp/${PARTITION_NUM_EFI_SYSTEM}"
    fi
    remote_sh rmdir "/tmp/${PARTITION_NUM_EFI_SYSTEM}"
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
  local old_kern_ver
  local new_kern_ver

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
  if [[ -z "${PARTITION_NUM_KERN_A}" ||
        -z "${PARTITION_NUM_KERN_B}" ||
        -z "${PARTITION_NUM_ROOT_A}" ||
        -z "${PARTITION_NUM_ROOT_B}" ]]; then
    die_notrace "Target is missing partition number info"
  fi

  learn_partition_and_ro

  if ! remote_sh "test -e '${FLAGS_partition}'"; then
    die_notrace "Could not find kernel partition on DUT; path='${FLAGS_partition}'"
  fi

  remote_sh uname -r -v
  old_kernel="${REMOTE_OUT}"

  new_kern_ver=$(readlink "/build/${FLAGS_board}/boot/vmlinuz" | cut -d- -f2-)

  check_kernelbuildtime "${new_kern_ver}"

  if [[ "${FLAGS_vboot}" -eq "${FLAGS_TRUE}" ]]; then
    make_kernelimage
  fi

  if [[ "${REMOTE_VERITY}" -eq "${FLAGS_FALSE}" ]]; then
    local remote_basedir
    if [[ "${REMOTE_NEEDS_ROOTFS_MOUNTED}" -eq "${FLAGS_TRUE}" ]]; then
      remote_sh mktemp -d /tmp/rootfs_mounted.XXXXXX
      remote_basedir="${REMOTE_OUT}"
      remote_sh mount "${FLAGS_rootfs}" "${remote_basedir}"
    else
      remote_sh mount -o remount,rw /
    fi

    # Getting the old kernel version from /boot/vmlinuz is the most reliable,
    # but this file doesn't exist on ARM.  In that case we fall back to the
    # most recently installed kernel in /lib/modules.
    if remote_sh "test -f '${remote_basedir}/boot/vmlinuz'"; then
      remote_sh readlink "${remote_basedir}/boot/vmlinuz"
      old_kern_ver="$(echo "${REMOTE_OUT}" | cut -d- -f2-)"
    else
      remote_sh "ls -t ${remote_basedir}/lib/modules | head -1"
      old_kern_ver="${REMOTE_OUT}"
    fi

    if [[ ${FLAGS_syslinux} -eq ${FLAGS_TRUE} ]]; then
      if [[ ${FLAGS_clean} -eq ${FLAGS_TRUE} ]]; then
        info "Cleaning /boot, copying syslinux and /boot"
        if [[ "${old_kern_ver}" != "${new_kern_ver}" ]]; then
          remote_sh rename "${old_kern_ver}" "${new_kern_ver}" \
                    "${remote_basedir}/boot/* 2>/dev/null" || true
        fi
        remote_send_to /build/"${FLAGS_board}"/boot/ "${remote_basedir}"/boot/ \
          --delete
      else
        info "Copying syslinux and /boot"
        remote_send_to /build/"${FLAGS_board}"/boot/ "${remote_basedir}"/boot/
      fi
      update_syslinux_kernel "${remote_basedir}"
    else
      info "Skipping syslinux and /boot (per request)"
    fi

    copy_kernelmodules "${remote_basedir}" "${old_kern_ver}" "${new_kern_ver}"

    if [[ ${FLAGS_firmware} -eq ${FLAGS_TRUE} ]]; then
      if [[ ${FLAGS_clean} -eq ${FLAGS_TRUE} ]]; then
        info "Cleaning and copying firmware (per request)"
        remote_send_to /build/"${FLAGS_board}"/lib/firmware/ \
                       "${remote_basedir}"/lib/firmware/ --delete
      else
        info "Copying firmware (per request)"
        remote_send_to /build/"${FLAGS_board}"/lib/firmware/ \
                       "${remote_basedir}"/lib/firmware/
      fi
    fi
    if [[ ${REMOTE_NEEDS_ROOTFS_MOUNTED} -eq ${FLAGS_TRUE} ]]; then
      remote_sh umount "${remote_basedir}"
      remote_sh rmdir "${remote_basedir}"
    fi
  fi

  if [[ "${FLAGS_vboot}" -eq "${FLAGS_TRUE}" ]]; then
    info "Copying vboot kernel image"
    copy_kernelimage
  else
    info "Skipping update of vboot (per request)"
  fi

  if [[ "${FLAGS_vmlinux}" -eq "${FLAGS_TRUE}" ]]; then
    info "Copying vmlinux.debug symbol to /usr/lib/debug/boot/ (per request)"
    copy_vmlinux
  else
    info "Skipping update of vmlinux.debug symbol"
  fi

  if [[ "${FLAGS_bootonce}" -eq "${FLAGS_TRUE}" || \
        "${FLAGS_ab_update}" -eq "${FLAGS_TRUE}" ]]; then
    info "Marking kernel partition ${FLAGS_partition} as boot once"
    mark_boot_once
  fi

  # An early kernel panic can prevent the normal sync on reboot.  Explicitly
  # sync for safety to avoid random file system corruption.
  remote_sh sync

  if [[ "${FLAGS_reboot}" -eq "${FLAGS_TRUE}" ]]; then
    remote_reboot

    remote_sh uname -r -v
    info "old kernel: ${old_kernel}"
    info "new kernel: ${REMOTE_OUT}"

    if [[ "${FLAGS_vboot}" -eq "${FLAGS_TRUE}" ]]; then
      check_buildid
    fi
  else
    info "Not rebooting (per request)"
  fi

  if [ -n "${FLAGS_boot_command}" ]; then
    info "Running boot command on remote"
    remote_sh "${FLAGS_boot_command}"
  fi
}

main "$@"
