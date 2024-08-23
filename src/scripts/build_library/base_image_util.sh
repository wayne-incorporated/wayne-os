# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CHROMEOS_CONFIG_DIR="${BOARD_ROOT}/usr/share/chromeos-config"

check_full_disk() {
  local prev_ret=$?

  # Disable die on error.
  set +e

  # See if we ran out of space.  Only show if we errored out via a trap.
  if [[ ${prev_ret} -ne 0 ]]; then
    local df=$(df -B 1M "${root_fs_dir}")
    if [[ ${df} == *100%* ]]; then
      error "Here are the biggest [partially-]extracted files (by disk usage):"
      # Send final output to stderr to match `error` behavior.
      sudo find "${root_fs_dir}" -xdev -type f -printf '%b %P\n' | \
        awk '$1 > 16 { $1 = $1 * 512; print }' | sort -n | tail -100 1>&2
      error "Target image has run out of space:"
      error "${df}"
    fi
  fi

   # Turn die on error back on.
  set -e
}

zero_free_space() {
  local fs_mount_point=$1

  if ! mountpoint -q "${fs_mount_point}"; then
    info "Not zeroing freespace in ${fs_mount_point} since it isn't a mounted" \
        "filesystem. This is normal for squashfs and ubifs partitions."
    return 0
  fi

  info "Zeroing freespace in ${fs_mount_point}"
  sudo fstrim -v "${fs_mount_point}"
}

log_rootfs_usage() {
  local fs_mount_point="$1"
  local -i block_size
  local -i free_blocks total_blocks used_blocks
  local -i free_bytes total_bytes used_bytes
  local -i total_nodes free_nodes used_nodes
  local -i total_mb free_mb used_mb

  block_size="$(stat -f -c "%S" "${fs_mount_point}")"

  total_blocks="$(stat -f -c "%b" "${fs_mount_point}")"
  free_blocks="$(stat -f -c "%f" "${fs_mount_point}")"
  used_blocks=$(( total_blocks - free_blocks ))

  total_nodes="$(stat -f -c "%c" "${fs_mount_point}")"
  free_nodes="$(stat -f -c "%d" "${fs_mount_point}")"
  used_nodes=$(( total_nodes - free_nodes ))

  total_bytes=$(( total_blocks * block_size ))
  free_bytes=$(( free_blocks * block_size ))
  used_bytes=$(( used_blocks * block_size ))
  total_mb=$(( total_bytes / (1024 * 1024) ))
  free_mb=$(( free_bytes / (1024 * 1024) ))
  used_mb=$(( used_bytes / (1024 * 1024) ))

  # Format the printout based on typical values (e.g. total_bytes and used_bytes
  # are typically 10 digits).
  info "Usage of the root filesystem:"
  info "Blocks:\t\tTotal: ${total_blocks}\t\tUsed: ${used_blocks}" \
    "\t\tFree: ${free_blocks}"
  info "Inodes:\t\tTotal: ${total_nodes}\t\tUsed: ${used_nodes}" \
    "\t\tFree: ${free_nodes}"
  info "Size (bytes):\tTotal: ${total_bytes}\tUsed: ${used_bytes}" \
    "\tFree: ${free_bytes}"
  info "Size (MiB):\t\tTotal: ${total_mb}\t\tUsed: ${used_mb}" \
    "\t\tFree: ${free_mb}"
}

# create_dev_install_lists updates package lists used by
# chromeos-base/dev-install
create_dev_install_lists() {
  local root_fs_dir=$1

  info "Building dev-install package lists"

  local pkgs=(
    portage
    virtual/target-os
    virtual/target-os-dev
    virtual/target-os-test
  )

  local pkgs_out=$(mktemp -d)
  local pids=()
  for pkg in "${pkgs[@]}" ; do
    (
      # We need to restrict the depgraph of the OS to binpkgs only as that is
      # used to determine what is baked into the rootfs.  When building that
      # from source, there's a lot more packages, but they aren't shipped, so
      # we want to make them installable after the fact.
      local usepkg
      if [[ "${pkg}" == "virtual/target-os" ]]; then
        usepkg="--usepkgonly"
      fi
      # Need to filter out BDEPENDS installed into the /.  We rely on the output
      # from portage to look like:
      #   R    sys-libs/zlib 1.2.11
      #   R    virtual/rust 1.47.0-r6 to /build/betty/
      emerge-${BOARD} --color n --pretend --quiet --emptytree --cols \
        --root-deps=rdeps --with-bdeps=n ${usepkg} ${pkg} | \
        awk '($2 ~ /\// && $4 == "to") {print $2 "-" $3}' | \
        sort > "${pkgs_out}/${pkg##*/}.packages"
      pipestatus=${PIPESTATUS[*]}
      [[ ${pipestatus// } -eq 0 ]]
    ) &
    pids+=( $! )
  done
  if ! wait "${pids[@]}"; then
    die_notrace "Generating lists failed"
  fi

  # bootstrap = portage - target-os
  comm -13 "${pkgs_out}/target-os.packages" \
    "${pkgs_out}/portage.packages" > "${pkgs_out}/bootstrap.packages"
  # Sanity check.  https://crbug.com/1015253
  if [[ ! -s "${pkgs_out}/bootstrap.packages" ]]; then
    grep ^ "${pkgs_out}"/*
    die "dev-install bootstrap.packages is empty!"
  fi

  # chromeos-base = target-os + portage - virtuals
  sort -u "${pkgs_out}/target-os.packages" "${pkgs_out}/portage.packages" \
    | grep -v "virtual/" \
     > "${pkgs_out}/chromeos-base.packages"

  # package.installable = target-os-dev + target-os-test - target-os + virtuals
  comm -23 <(sort -u "${pkgs_out}/target-os-dev.packages" \
                     "${pkgs_out}/target-os-test.packages") \
    "${pkgs_out}/target-os.packages" \
    > "${pkgs_out}/package.installable"
  grep "virtual/" "${pkgs_out}/target-os.packages" | sort \
    >> "${pkgs_out}/package.installable"

  # Copy the file over for chromite to process.
  sudo mkdir -p "${BOARD_ROOT}/build/dev-install"
  sudo mv "${pkgs_out}/package.installable" "${BOARD_ROOT}/build/dev-install/"

  # installable_commands is the list of all programs installed into ${PATH} from
  # package.installable.
  local installable_packages=()
  mapfile -t installable_packages \
    < "${BOARD_ROOT}/build/dev-install/package.installable"
  qlist-"${BOARD}" -e "${installable_packages[@]}" | \
    grep -E '^(/usr)?/s?bin/' | \
    awk -F/ '{print $NF}' | \
    sort -u > "${pkgs_out}/installable_commands"
  sudo cp "${pkgs_out}/installable_commands" \
    "${root_fs_dir}/usr/share/dev-install/installable_commands"

  local package_provided_dir="${root_fs_dir}/usr/share/dev-install/"
  package_provided_dir+="portage/make.profile/package.provided"

  sudo mkdir -p \
    "${package_provided_dir}" \
    "${root_fs_dir}/usr/share/dev-install/rootfs.provided"
  sudo cp "${pkgs_out}/bootstrap.packages" \
    "${root_fs_dir}/usr/share/dev-install/"
  sudo cp "${pkgs_out}/chromeos-base.packages" \
    "${root_fs_dir}/usr/share/dev-install/rootfs.provided/"

  # Copy the toolchain settings which are fixed at build_image time.
  sudo cp "${BOARD_ROOT}/etc/portage/profile/package.provided" \
    "${package_provided_dir}/toolchain.conf"

  # Copy the profile stubbed packages which are always disabled for the board.
  # TODO(vapier): This doesn't currently respect the profile or its parents.
  local overlay="${CHROOT_TRUNK_DIR}/src/third_party/chromiumos-overlay"
  sudo cp \
    "${overlay}/profiles/targets/chromeos/package.provided" \
    "${package_provided_dir}/board-profile.conf"

  rm -r "${pkgs_out}"
}

# Load a single variable from a bash file.
# $1 - Path to the file.
# $2 - Variable to get.
_get_variable() {
  local filepath=$1
  local variable=$2
  local lockfile="${filepath}.lock"

  if [[ -e "${filepath}" ]]; then
    (
      flock 201
      . "${filepath}"
      if [[ "${!variable+set}" == "set" ]]; then
        echo "${!variable}"
      fi
    ) 201>"${lockfile}"
  fi
}

install_libc_for_abi() {
  # We need to install libc manually from the cross toolchain.
  # TODO: Improve this? It would be ideal to use emerge to do this.
  local root_fs_dir="$1"
  local abi="$2"
  PKGDIR="/var/lib/portage/pkgs"

  local pkgs=( "glibc" )
  local pkg_ver_str=( "LIBC_VERSION" )
  local exclude_gconv=false
  if [[ "$3" == "--copy-cxx-runtime" ]]; then
    # Normally only glibc gets installed here since it is not built per board
    # while other "standard" libraries like the C++ libraries get installed by
    # ebuilds. In the case of NaCl on Arm64, we need to install a second set of
    # "standard" libraries for Arm32 to run NaCl binaries in Arm32 mode.
    # So we'll install glibc and C++ libraries here using prebuilts for host
    # cross-<abi>/<library> packages and not rely on ebuilds.
    # This is a bit hacky but is only for a "short" while.
    pkgs+=( "llvm-libunwind" "libcxx" )
    pkg_ver_str+=("LIBGCC_VERSION" "LIBCXX_VERSION")
    # gconv_strip.py does not like two set of gconv files but for
    # arm32 + aarch64 multilib for NaCl, we have two set of files.
    # As long as the second set for extra ABI is not needed for NaCl, we can
    # just skip installing them for the arm32 abi while keeping aarch64.
    exclude_gconv=true
  fi

  local idx pkg pkg_version pkg_atom pkg_path pkg_excludes pkg_comp
  for (( idx = 0; idx < ${#pkgs[@]}; idx++ )); do
    pkg="${pkgs[${idx}]}"
    pkg_version="$(_get_variable "${BOARD_ROOT}/${SYSROOT_SETTINGS_FILE}" \
      "${pkg_ver_str[${idx}]}")"
    pkg_atom="cross-${abi}/${pkg}-${pkg_version}"
    pkg_path="${PKGDIR}/${pkg_atom}.tbz2"
    pkg_decompressor="$(detect_decompression_tool "${pkg_path}")"
    if [[ "${pkg}" == "glibc" ]]; then
      # LIBC_PATH needs to be export for later use in dev_image_util.sh
      # to extract debug symbols.
      # TODO(b/223285139): Change to export an array of packages instead
      # since we should have really extract debug info for all of them.
      export LIBC_PATH="${pkg_path}"
      export LIBC_DECOMPRESSOR="${pkg_decompressor}"
    fi

    if [[ ! -e "${pkg_path}" ]]; then
      sudo emerge --nodeps -gf "=${pkg_atom}"
    fi

    # Strip out files we don't need in the final image at runtime.
    pkg_excludes=(
      # Compile-time headers.
      'usr/include' 'sys-include'
      # Link-time objects.
      '*.[ao]'
      # Debug commands not used by normal runtime code.
      'usr/bin/'{getent,ldd}
      # LD_PRELOAD objects for debugging.
      'lib*/lib'{memusage,pcprofile,SegFault}.so 'usr/lib*/audit'
      # We only use files & dns with nsswitch, so throw away the others.
      'lib*/libnss_'{compat,db,hesiod,nis,nisplus}'*.so*'
      # This is only for very old packages which we don't have.
      'lib*/libBrokenLocale*.so*'
   )
   if [[ "${exclude_gconv}" == true ]]; then
      pkg_excludes+=(
        'usr/lib/gconv'
        'usr/lib64/gconv'
      )
    fi
    info_run sudo tar -I"${pkg_decompressor}" -xpf "${pkg_path}" \
      -C "${root_fs_dir}" "./usr/${abi}" \
      --strip-components=3 "${pkg_excludes[@]/#/--exclude=}"
  done
}

install_libc() {
  local root_fs_dir="$1"

  # Until nacl goes away completely, we actually need to run it in arm32
  # mode on arm64 hosts. This will get the basic C/C++ libraries installed
  # onto the device.
  if [[ "${CHOST}" == "aarch64-cros-linux-gnu" ]]; then
    install_libc_for_abi "${root_fs_dir}" "armv7a-cros-linux-gnueabihf" \
      "--copy-cxx-runtime"
  fi

  install_libc_for_abi "${root_fs_dir}" "${CHOST}"
}

inject_system_wide_scudo() {
  local root_fs_dir="$1"
  info "'system_wide_scudo' enabled; Injecting scudo..."
  local arch
  local libdir
  case "${ARCH}" in
    x86)
      arch='i386'
      libdir='lib'
      ;;
    amd64)
      arch='x86_64'
      libdir='lib64'
      ;;
    arm)
      arch='armhf'
      libdir="lib"
      ;;
    arm64)
      arch='aarch64'
      libdir="lib64"
      ;;
    *) die "Inject scudo: unknown ARCH '${ARCH}'";;
  esac
  local libname="libclang_rt.scudo_standalone-${arch}.so"
  local rootfs_scudo_loc="/usr/${libdir}/${libname}"
  local preload_file="${root_fs_dir}/etc/ld.so.preload"
  if [[ -f "${preload_file}" ]]; then
    die "Inject scudo: preload '${preload_file}' already exists"
  fi
  local absolute_scudo_loc="${root_fs_dir}${rootfs_scudo_loc}"
  if [[ -f "${absolute_scudo_loc}" ]]; then
    echo "${rootfs_scudo_loc}" | sudo tee "${preload_file}" > /dev/null
    info "Wrote ${rootfs_scudo_loc} to ${preload_file}"
  else
    die "Inject scudo: lib '${absolute_scudo_loc}' does NOT exist"
  fi
}

create_base_image() {
  local image_name=$1
  local rootfs_verification_enabled=$2
  local image_type="usb"

  info "Entering create_base_image $*"

  if [[ "${FLAGS_disk_layout}" != "default" ]]; then
    image_type="${FLAGS_disk_layout}"
  else
    if should_build_image ${CHROMEOS_FACTORY_INSTALL_SHIM_NAME}; then
      image_type="factory_install"
    fi
  fi

  check_valid_layout "base"
  check_valid_layout "${image_type}"

  info "Using image type ${image_type}"
  get_disk_layout_path
  info "Using disk layout ${DISK_LAYOUT_PATH}"
  root_fs_dir="${BUILD_DIR}/rootfs"
  root_cros_vdb_strip_prefix="${root_fs_dir}"
  stateful_fs_dir="${BUILD_DIR}/stateful"
  esp_fs_dir="${BUILD_DIR}/esp"

  trap "delete_prompt" EXIT
  mkdir "${root_fs_dir}" "${stateful_fs_dir}" "${esp_fs_dir}"
  build_gpt_image "${BUILD_DIR}/${image_name}" "${image_type}"

  # Try to get all of the dirty pages written to disk, so that mount doesn't
  # return EAGAIN.
  info "Syncing ${BUILD_DIR}/${image_name}."
  sync -f "${BUILD_DIR}/${image_name}"

  trap "check_full_disk ; unmount_image ; delete_prompt" EXIT
  mount_image "${BUILD_DIR}/${image_name}" "${root_fs_dir}" \
    "${stateful_fs_dir}" "${esp_fs_dir}"

  # Create symlinks so that /usr/local/usr based directories are symlinked to
  # /usr/local/ directories e.g. /usr/local/usr/bin -> /usr/local/bin, etc.
  setup_symlinks_on_root "." \
    "${stateful_fs_dir}/var_overlay" "${stateful_fs_dir}"

  # install libc
  install_libc "${root_fs_dir}"

  if should_build_image ${CHROMEOS_FACTORY_INSTALL_SHIM_NAME}; then
    # Install our custom factory install kernel with the appropriate use flags
    # to the image.
    emerge_custom_kernel "${root_fs_dir}"
  fi

  # We "emerge --root=${root_fs_dir} --root-deps=rdeps --usepkgonly" all of the
  # runtime packages for chrome os. This builds up a chrome os image from
  # binary packages with runtime dependencies only.  We use INSTALL_MASK to
  # trim the image size as much as possible.
  emerge_to_image --root="${root_fs_dir}" ${BASE_PACKAGE}

  # Inject scudo system wide if system_wide_scudo is enabled.
  if has "system_wide_scudo" in "$(portageq-"${BOARD}" envvar USE)"; then
    # We do inject at this stage (and not during build_packages) because
    # some unit tests fail when tested with Scudo. This isn't an inherent
    # problem with Scudo, but instead is a problem with shared memory regions
    # between allocators. If the host is using GNU Allocator and the VM is
    # using Scudo, we're going to end up with a lot of memory errors.
    inject_system_wide_scudo "${root_fs_dir}"
  fi

  # Run depmod to recalculate the kernel module dependencies.
  run_depmod "${BOARD_ROOT}" "${root_fs_dir}"

  # Generate the license credits page for the packages installed on this
  # image in a location that will be used by Chrome.
  info "Generating license credits page. Time:"
  local dir_name="${root_fs_dir}/opt/google/chrome/resources"
  sudo mkdir -p "${dir_name}"
  local license_path="${dir_name}/about_os_credits.html.gz"
  time info_run sudo "${GCLIENT_ROOT}/chromite/licensing/licenses" \
    --board="${BOARD}" \
    --os-version="${CHROMEOS_VERSION_STRING}" \
    --milestone-version="${CHROME_BRANCH}" \
    --log-level error \
    --generate-licenses \
    --output "${license_path}" \
    --compress-output
  # Copy the license credits file to ${BUILD_DIR} so that is will be uploaded
  # as artifact later in ArchiveStage.
  if [[ -r "${license_path}" ]]; then
    cp "${license_path}" "${BUILD_DIR}/license_credits.html"
  fi

  # Remove unreferenced gconv charsets.
  # gconv charsets are .so modules loaded dynamically by iconv_open(3),
  # installed by glibc. Applications using them don't explicitly depend on them
  # and we don't known which ones will be used until all the applications are
  # installed. This script looks for the charset names on all the binaries
  # installed on the the ${root_fs_dir} and removes the unreferenced ones.
  info_run sudo "${CHROMITE_BIN}/gconv_strip" "${root_fs_dir}"

  # Run ldconfig to create /etc/ld.so.cache.
  run_ldconfig "${root_fs_dir}"

  # Run udevadm to generate /etc/udev/hwdb.bin
  run_udevadm_hwdb "${root_fs_dir}"

  # Clean-up the *.hwdb, we don't need them at runtime
  # but we cannot put them in the INSTALL_MASK else
  # the hwdb.bin generation above won't do anything.
  sudo rm -rf "${root_fs_dir}/lib/udev/hwdb.d" \
              "${root_fs_dir}/etc/udev/hwdb.d" || :

  # File searches /usr/share even if it's installed in /usr/local.  Add a
  # symlink so it works in dev images & when using dev_install.  Unless it's
  # already installed.  https://crbug.com/210493
  if [[ ! -x "${root_fs_dir}/usr/bin/file" ]]; then
    sudo mkdir -p "${root_fs_dir}/usr/share/misc"
    sudo ln -s /usr/local/share/misc/magic.mgc \
      "${root_fs_dir}/usr/share/misc/magic.mgc"
  fi

  # Portage hardcodes /usr/share/portage internally even when it's installed
  # in /usr/local, so add a symlink as needed so it works in dev images & when
  # using dev_install.
  if [[ ! -d "${root_fs_dir}/usr/share/portage" ]]; then
    sudo ln -s /usr/local/share/portage "${root_fs_dir}/usr/share/portage"
  fi

  # If python isn't installed into the rootfs, we'll assume it'll be installed
  # into /usr/local later on.  Create symlinks in the rootfs so python still
  # works even when not in the rootfs.  This is needed because Gentoo creates
  # wrappers with hardcoded paths to the rootfs (e.g. python-exec).
  local pyversions=(
    # Querying versions is a bit fun.  We don't know precisely what will be
    # installed in /usr/local, so just query what is available in the sysroot.
    # The qlist output is: dev-lang/python:3.6
    $("qlist-${BOARD}" -ICSe 'dev-lang/python' | cut -d: -f2)
  )
  local path python_paths=(
    "/etc/env.d/python"
    "${pyversions[@]/#//usr/lib/python}"
    "/usr/lib/python-exec"
    "/usr/lib/portage"
    "/usr/bin/python"
    "/usr/bin/python3"
    "/usr/bin/python-exec2c"
    "${pyversions[@]/#//usr/bin/python}"
  )
  if [[ -d "${root_fs_dir}/lib64" ]]; then
    python_paths+=( "${pyversions[@]/#//usr/lib64/python}" )
  fi
  for path in "${python_paths[@]}"; do
    if [[ ! -e "${root_fs_dir}${path}" && ! -L "${root_fs_dir}${path}" ]]; then
      sudo ln -sf "/usr/local${path}" "${root_fs_dir}${path}"
    fi
  done

  # Set /etc/lsb-release on the image.
  local official_flag=
  if [[ "${CHROMEOS_OFFICIAL:-0}" == "1" ]]; then
    official_flag="--official"
  fi

  # Get the build info of ARC if available.
  if type get_arc_build_info &>/dev/null; then
    # This will set CHROMEOS_ARC_*.
    get_arc_build_info "${root_fs_dir}"
  fi
  local arc_flags=()
  if [[ -n "${CHROMEOS_ARC_VERSION}" ]]; then
    arc_flags+=("--arc_version=${CHROMEOS_ARC_VERSION}")
  fi
  if [[ -n "${CHROMEOS_ARC_ANDROID_SDK_VERSION}" ]]; then
    arc_flags+=("--arc_android_sdk_version=${CHROMEOS_ARC_ANDROID_SDK_VERSION}")
  fi

  local builder_path=
  if [[ -n "${FLAGS_builder_path}" ]]; then
    builder_path="--builder_path=${FLAGS_builder_path}"
  fi

  local unibuild_flag=
  if [[ -d "${CHROMEOS_CONFIG_DIR}" ]]; then
    unibuild_flag="--unibuild"
  fi

  info_run "${CHROMITE_BIN}/cros_set_lsb_release" \
    --sysroot="${root_fs_dir}" \
    --board="${BOARD}" \
    ${unibuild_flag} \
    ${builder_path} \
    --keyset="devkeys" \
    --version_string="${CHROMEOS_VERSION_STRING}" \
    --auserver="${CHROMEOS_VERSION_AUSERVER}" \
    --devserver="${CHROMEOS_VERSION_DEVSERVER}" \
    ${official_flag} \
    --buildbot_build="${BUILDBOT_BUILD:-"N/A"}" \
    --track="${CHROMEOS_VERSION_TRACK:-"developer-build"}" \
    --branch_number="${CHROMEOS_BRANCH}" \
    --build_number="${CHROMEOS_BUILD}" \
    --chrome_milestone="${CHROME_BRANCH}" \
    --patch_number="${CHROMEOS_PATCH}" \
    "${arc_flags[@]}"

  # Copy the full lsb-release into the initramfs build root.
  if has "minios" "$(portageq-"${BOARD}" envvar USE)"; then
    sudo mkdir -p "${BOARD_ROOT}/build/initramfs/etc"
    sudo cp "${root_fs_dir}/etc/lsb-release" \
      "${BOARD_ROOT}/build/initramfs/etc/"
  fi

  # Set /etc/os-release on the image.
  # Note: fields in /etc/os-release can come from different places:
  # * /etc/os-release itself with docrashid
  # * /etc/os-release.d for fields created with do_osrelease_field
  info_run sudo "${CHROMITE_BIN}/cros_generate_os_release" \
    --root="${root_fs_dir}" \
    --version="${CHROME_BRANCH}" \
    --build_id="${CHROMEOS_VERSION_STRING}"

  # Create the boot.desc file which stores the build-time configuration
  # information needed for making the image bootable after creation with
  # cros_make_image_bootable.
  create_boot_desc "${image_type}"

  # Write out the GPT creation script.
  # This MUST be done before writing bootloader templates else we'll break
  # the hash on the root FS.
  write_partition_script "${image_type}" \
    "${root_fs_dir}/${PARTITION_SCRIPT_PATH}"
  sudo chown root:root "${root_fs_dir}/${PARTITION_SCRIPT_PATH}"

  # Populates the root filesystem with legacy bootloader templates
  # appropriate for the platform.  The autoupdater and installer will
  # use those templates to update the legacy boot partition (12/ESP)
  # on update.
  # (This script does not populate vmlinuz.A and .B needed by syslinux.)
  local enable_rootfs_verification=
  if [[ ${rootfs_verification_enabled} -eq ${FLAGS_TRUE} ]]; then
    enable_rootfs_verification="--enable_rootfs_verification"
  fi

  # If the KERN-A partition is of type "reserved", there is no kernel.
  # Skip the preparation of a bootable kernel partition.
  local has_bootable_kernel=1
  local kernel_part_num="$(get_layout_partition_number "${image_type}" KERN-A)"
  local kernel_part_type="$(get_type "${image_type}" "${kernel_part_num}")"
  if [[ "${kernel_part_type}" == "reserved" ]]; then
    has_bootable_kernel=0
  fi

  if [[ "${has_bootable_kernel}" -eq 1 ]]; then
    info_run "${BUILD_LIBRARY_DIR}/create_legacy_bootloader_templates.sh" \
      --arch=${ARCH} \
      --board=${BOARD} \
      --image_type="${image_type}" \
      --to="${root_fs_dir}"/boot \
      --boot_args="${FLAGS_boot_args}" \
      --enable_serial="${FLAGS_enable_serial}" \
      --loglevel="${FLAGS_loglevel}" \
      ${enable_rootfs_verification}
  fi

  # Run board-specific build image function, if available.
  if type board_finalize_base_image &>/dev/null; then
    board_finalize_base_image
  fi

  # Clean up symlinks so they work on a running target rooted at "/".
  # Here development packages are rooted at /usr/local.  However, do not
  # create /usr/local or /var on host (already exist on target).
  setup_symlinks_on_root . "/var" "${stateful_fs_dir}"

  # Our masking of files will implicitly leave behind a bunch of empty
  # dirs.  We can't differentiate between empty dirs we want and empty
  # dirs we don't care about, so just prune ones we know are OK.
  sudo find "${root_fs_dir}/usr/include" -depth -type d -exec rmdir {} + \
    2>/dev/null || :

  setup_etc_shadow "${root_fs_dir}"

  # Release images do not include these, so install it for dev images.
  sudo mkdir -p "${root_fs_dir}/usr/local/bin/"
  sudo cp -a "${BOARD_ROOT}"/usr/bin/{getent,ldd} \
    "${root_fs_dir}/usr/local/bin/"

  if [[ -d "${root_fs_dir}/usr/share/dev-install" ]]; then
    # Create a package for the dev-only files installed in /usr/local
    # of a base image. This package can later be downloaded with
    # dev_install running from a base image.
    # Files installed in /usr/local/var were already installed in
    # stateful since we created a symlink for those. We ignore the
    # symlink in this package since the directory /usr/local/var
    # exists in the target image when dev_install runs.
    info_run sudo tar -cf "${BOARD_ROOT}/packages/dev-only-extras.tar.xz" \
      -I 'xz -9 -T0' --exclude=var -C "${root_fs_dir}/usr/local" .

    if should_build_image ${CHROMEOS_FACTORY_INSTALL_SHIM_NAME}; then
      info "Skipping dev-install lists for factory shim images."
    else
      create_dev_install_lists "${root_fs_dir}"
    fi
  fi

  # Generate DLCs and copy their metadata to the rootfs + factory install DLC
  # images into stateful partition.
  if should_build_image ${CHROMEOS_FACTORY_INSTALL_SHIM_NAME}; then
    info "Skipping DLC copying for factory shim images."
  else
    info_run build_dlc --sysroot="${BOARD_ROOT}" --rootfs="${root_fs_dir}" \
      --stateful="${stateful_fs_dir}" --board="${BOARD}" --factory-install
  fi

  restore_fs_contexts "${BOARD_ROOT}" "${root_fs_dir}" "${stateful_fs_dir}"

  # Move the bootable kernel images out of the /boot directory to save
  # space.  We put them in the $BUILD_DIR so they can be used to write
  # the bootable partitions later.
  mkdir -p "${BUILD_DIR}/boot_images"

  # The standard /boot location may be optionally including kernel image in
  # final build image iff:
  #
  # - boards that boot with legacy bioses need the kernel on the boot image
  # - boards with coreboot/depthcharge boot from a boot partition.
  local cpmv
  local boot_dir="${root_fs_dir}/boot"
  if has "include_vmlinuz" "$(portageq-"${BOARD}" envvar USE)"; then
    cpmv="cp"
  else
    cpmv="mv"
  fi

  [ -e "${boot_dir}"/Image-* ] && \
    sudo "${cpmv}" "${boot_dir}"/Image-* "${BUILD_DIR}/boot_images"
  [ -L "${boot_dir}"/zImage-* ] && \
    sudo "${cpmv}" "${boot_dir}"/zImage-* "${BUILD_DIR}/boot_images"
  [ -e "${boot_dir}"/vmlinuz-* ] && \
    sudo "${cpmv}" "${boot_dir}"/vmlinuz-* "${BUILD_DIR}/boot_images"
  [ -L "${boot_dir}"/vmlinuz ] && \
    sudo "${cpmv}" "${boot_dir}"/vmlinuz "${BUILD_DIR}/boot_images"

  # Calculate package sizes within the built rootfs for reporting purposes.
  # Use sudo to access some paths that are unreadable as non-root.
  # shellcheck disable=2154
  (sudo BUILD_API_METRICS_LOG="${BUILD_API_METRICS_LOG}" \
     -- \
     "${GCLIENT_ROOT}/chromite/scripts/pkg_size" \
        --root "${root_fs_dir}" \
        --image-type 'base' \
        --partition-name 'rootfs') \
     > "${BUILD_DIR}/${image_name}-package-sizes.json"

  # Zero rootfs free space to make it more compressible so auto-update
  # payloads become smaller.
  zero_free_space "${root_fs_dir}"

  log_rootfs_usage "${root_fs_dir}"

  unmount_image
  trap - EXIT

  USE_DEV_KEYS=
  if should_build_image ${CHROMEOS_FACTORY_INSTALL_SHIM_NAME}; then
    USE_DEV_KEYS="--use_dev_keys"
  fi

  if [[ "${skip_kernelblock_install}" -ne 1 \
    && "${has_bootable_kernel}" -eq 1 ]]; then
    # Place flags before positional args.
    info_run "${SCRIPTS_DIR}/bin/cros_make_image_bootable" "${BUILD_DIR}" \
      ${image_name} ${USE_DEV_KEYS} --adjust_part="${FLAGS_adjust_part}"
  fi

  # Build minios kernel and put it in the MINIOS-A partition of the image.
  if has "minios" "$(portageq-"${BOARD}" envvar USE)"; then
    info_run build_minios --board "${BOARD}" \
      --image "${BUILD_DIR}/${image_name}" \
      --version "${CHROMEOS_VERSION_STRING}"
  fi
}
