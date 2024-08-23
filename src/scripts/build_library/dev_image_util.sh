# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Shell function library for functions specific to creating dev
# images from base images.  The main function for export in this
# library is 'install_dev_packages'.


# Modifies an existing image to add development packages.
# Takes as an arg the name of the image to be created.
install_dev_packages() {
  local image_name=$1

  info "Adding developer packages to ${image_name}"

  trap "check_full_disk ; unmount_image ; delete_prompt" EXIT
  mount_image "${BUILD_DIR}/${image_name}" "${root_fs_dir}" \
    "${stateful_fs_dir}" "${esp_fs_dir}"

  # Determine the root dir for developer packages.
  local root_dev_dir="${root_fs_dir}/usr/local"

  # Symlink to /etc/{passwd,group,pam.d} from inside the developer package
  # root, so ebuilds can create users, groups, and set pam rules at build time.
  sudo mkdir -p "${root_dev_dir}/etc"
  sudo ln -s ../../../etc/passwd "${root_dev_dir}/etc/passwd"
  sudo ln -s ../../../etc/group "${root_dev_dir}/etc/group"
  sudo ln -s ../../../etc/pam.d "${root_dev_dir}/etc/pam.d"

  # Install dev-specific init scripts into / from chromeos-dev-root.
  emerge_to_image --root="${root_fs_dir}" chromeos-dev-root

  # Install developer packages.
  emerge_to_image --root="${root_dev_dir}" virtual/target-os-dev

  # Run depmod to recalculate the kernel module dependencies.
  run_depmod "${BOARD_ROOT}" "${root_fs_dir}"

  # Copy over the libc debug info so that gdb
  # works with threads and also for a better debugging experience.
  sudo mkdir -p "${root_fs_dir}/usr/local/usr/lib/debug"
  info_run sudo tar -I"${LIBC_DECOMPRESSOR}" -xpf "${LIBC_PATH}" \
    -C "${root_fs_dir}/usr/local/usr/lib/debug" \
    ./usr/lib/debug/usr/${CHOST} --strip-components=6
  # Since gdb only looks in /usr/lib/debug, symlink the /usr/local
  # path so that it is found automatically.
  sudo ln -sfT /usr/local/usr/lib/debug "${root_fs_dir}/usr/lib/debug"

  # Re-run ldconfig to fix /etc/ld.so.cache.
  run_ldconfig "${root_fs_dir}"

  # Additional changes to developer image.
  sudo mkdir -p "${root_fs_dir}/root"

  # Leave core files for developers to inspect.
  sudo touch "${root_fs_dir}/root/.leave_core"

  # If bash is not installed on rootfs, we'll need a  bash symlink.
  # Otherwise, emerge won't work.
  if [[ ! -e "${root_fs_dir}"/bin/bash ]]; then
    info "Fixing bash path for developer and test images."
    sudo ln -sf /usr/local/bin/bash "${root_fs_dir}"/bin/bash
  fi

  setup_etc_shadow "${root_fs_dir}"

  restore_fs_contexts "${BOARD_ROOT}" "${root_fs_dir}" "${stateful_fs_dir}"

  info "Developer image built and stored at ${image_name}"

  unmount_image
  trap - EXIT

  if [[ ${skip_kernelblock_install} -ne 1 ]]; then
    if should_build_image ${image_name}; then
      ${SCRIPTS_DIR}/bin/cros_make_image_bootable "${BUILD_DIR}" \
        ${image_name} --force_developer_mode
    fi
  fi

  # Update MINIOS-A partition with developer mode image. This does not rebuild
  # the MiniOS image. It only enables/adds dev-mode flags.
  if has "minios" "$(portageq-"${BOARD}" envvar USE)"; then
    build_minios --mod-for-dev --board "${BOARD}" \
      --image "${BUILD_DIR}/${image_name}" \
      --version "${CHROMEOS_VERSION_STRING}"
  fi
}
