# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Shell library for functions and initialization private to
# build_image, and not specific to any particular kind of image.
#
# TODO(jrbarnette):  There's nothing holding this code together in
# one file aside from its lack of anywhere else to go.  Probably,
# this file should get broken up or otherwise reorganized.

EMERGE_BOARD_CMD="${CHROMITE_BIN}/parallel_emerge"
EMERGE_BOARD_CMD="$EMERGE_BOARD_CMD --board=$BOARD"

if [[ $FLAGS_jobs -ne -1 ]]; then
  EMERGE_JOBS="--jobs=$FLAGS_jobs"
fi

make_salt() {
  # It is not important that the salt be cryptographically strong; it just needs
  # to be different for each release. The purpose of the salt is just to ensure
  # that if someone collides a block in one release, they can't reuse it in
  # future releases.
  xxd -l 32 -p -c 32 /dev/urandom
}

# Create a boot.desc file containing flags used to create this image.
# The format is a bit fragile -- make sure get_boot_desc parses it back.
create_boot_desc() {
  local image_type=$1

  local enable_rootfs_verification_flag=""
  if [[ ${FLAGS_enable_rootfs_verification} -eq ${FLAGS_TRUE} ]]; then
    enable_rootfs_verification_flag="--enable_rootfs_verification"
  fi

  [ -z "${FLAGS_verity_salt}" ] && FLAGS_verity_salt=$(make_salt)
  cat <<EOF > ${BUILD_DIR}/boot.desc
  --board=${BOARD}
  --image_type=${image_type}
  --arch="${ARCH}"
  --keys_dir="${VBOOT_DEVKEYS_DIR}"
  --boot_args="${FLAGS_boot_args}"
  --nocleanup_dirs
  --verity_algorithm=sha256
  --enable_serial="${FLAGS_enable_serial}"
  --loglevel="${FLAGS_loglevel}"
  ${enable_rootfs_verification_flag}
EOF
}

# Extract flags saved in boot.desc and return it via the boot_desc_flags array.
get_boot_desc() {
  local boot_desc_file=$1
  local line

  if [[ ! -r ${boot_desc_file} ]]; then
    warn "${boot_desc_file}: cannot be read"
    return 1
  fi

  # Do not mark this local as it is the return value.
  boot_desc_flags=()
  while read line; do
    if [[ -z ${line} ]]; then
      continue
    fi

    # Hand extract the quotes to deal with random content in the value.
    # e.g. When you pass --boot_args="foo=\"\$bar'" to build_image, we write it
    # out in the file as --boot_args="foo="$bar'" which is a parse error if we
    # tried to eval it directly.
    line=$(echo "${line}" | sed -r \
      -e 's:^\s+::;s:\s+$::' -e "s:^(--[^=]+=)([\"'])(.*)\2$:\1\3:")
    boot_desc_flags+=( "${line}" )
  done <"${boot_desc_file}"
}

# Utility function for moving the build directory to the output root.
move_image() {
  local source="$1"
  local destination="$2"
  # If the output_root isn't the same as the build_root, move the resulting
  # image to the correct place in output_root.
  if [[ "${source}" != "${destination}" ]]; then
    info "Moving the image to: ${destination}."
    mkdir -p "${destination}"
    mv "${source}"/* "${destination}"
    rmdir "${source}"
  fi
}

delete_prompt() {
  echo "An error occurred in your build so your latest output directory" \
    "is invalid."

  # Only prompt if both stdin and stdout are a tty. If either is not a tty,
  # then the user may not be present, so we shouldn't bother prompting.
  if [ -t 0 -a -t 1 -a "${USER}" != 'chrome-bot' ]; then
    read -p "Would you like to delete the output directory (y/N)? " SURE
    SURE="${SURE:0:1}" # Get just the first character.
  else
    SURE="y"
    echo "Running in non-interactive mode so deleting output directory."
  fi
  if [ "${SURE}" == "y" ] ; then
    sudo rm -rf "${BUILD_DIR}"
    echo "Deleted ${BUILD_DIR}"
  else
    move_image "${BUILD_DIR}" "${OUTPUT_DIR}"
    echo "Not deleting ${OUTPUT_DIR}."
  fi
}

# Basic command to emerge binary packages into the target image.
# Arguments to this command are passed as addition options/arguments
# to the basic emerge command.
emerge_to_image() {
  set -- ${EMERGE_BOARD_CMD} --root-cros-vdb-strip-prefix="${root_cros_vdb_strip_prefix}" \
    --root-deps=rdeps --usepkgonly -v --with-bdeps=n "$@" ${EMERGE_JOBS}
  info_run sudo -E "$@"
}

# Create the /etc/shadow file with all the right entries.
SHARED_USER_NAME="chronos"
SHARED_USER_PASSWD_FILE="/etc/shared_user_passwd.txt"
setup_etc_shadow() {
  local root=$1
  local shadow="${root}/etc/shadow"
  local passwd="${root}/etc/passwd"
  local line
  local cmds
  local sed_cmds=()

  # Remove the file completely so we know it is fully initialized
  # with the correct permissions.  Note: we're just making it writable
  # here to simplify scripting; permission fixing happens at the end.
  cmds=(
    "rm -f '${shadow}'"
    "install -m 666 /dev/null '${shadow}'"
  )
  sudo_multi "${cmds[@]}"

  # Create shadow entries for all accounts in /etc/passwd that says
  # they expect it.  Otherwise, pam will not let people even log in
  # via ssh keyauth.  http://crbug.com/361864
  while read -r line; do
    local acct=$(cut -d: -f1 <<<"${line}")
    local pass=$(cut -d: -f2 <<<"${line}")

    # For the special shared user account, load the shared user password
    # if one has been set.
    if [[ ${acct} == "${SHARED_USER_NAME}" &&
          -e "${SHARED_USER_PASSWD_FILE}" ]]; then
      pass=$(<"${SHARED_USER_PASSWD_FILE}")
    fi

    case ${pass} in
    # Login is disabled -> do nothing.
    '!') ;;
    # Password will be set later by tools.
    '*') ;;
    # Password is shadowed.
    'x')
      echo "${acct}:*:::::::" >> "${shadow}"
      ;;
    # Password is set directly.
    *)
      echo "${acct}:${pass}:::::::" >> "${shadow}"

      # This is a sed command to replace the password field with an 'x' instead
      # of the existing hashed password. We use ! as the sed separator because
      # it's guaranteed not to appear in a hashed password field (see passwd(5)
      # and crypt(3) man pages)
      sed_cmds+=("-e" "s!^${acct}:${pass}:!${acct}:x:!")
      ;;
    esac
  done <"${passwd}"

  if [[ "${#sed_cmds[@]}" -gt 0 ]]; then
    sudo sed -i "${sed_cmds[@]}" "${passwd}"
  fi

  # Now make the settings sane.
  cmds=(
    "chown 0:0 '${shadow}'"
    "chmod 600 '${shadow}'"
  )
  sudo_multi "${cmds[@]}"
}

# ldconfig cannot generate caches for non-native arches.
# Use qemu & the native ldconfig to work around that.
# http://crbug.com/378377
run_ldconfig() {
  local root_fs_dir=$1
  case ${ARCH} in
  arm)
    sudo qemu-arm "${root_fs_dir}"/sbin/ldconfig -r "${root_fs_dir}";;
  arm64)
    sudo qemu-aarch64 "${root_fs_dir}"/sbin/ldconfig -r "${root_fs_dir}";;
  mips)
    sudo qemu-mipsel "${root_fs_dir}"/sbin/ldconfig -r "${root_fs_dir}";;
  x86|amd64)
    sudo ldconfig -r "${root_fs_dir}";;
  *)
    die "Unable to run ldconfig for ARCH ${ARCH}"
  esac
}

# Runs "depmod" to recalculate the kernel module dependencies.
# Args:
#   board_root: root of the build output for the board
#   root_fs_dir: target root file system mount point
run_depmod() {
  local board_root="$1"
  local root_fs_dir="$2"

  local root_fs_modules_path="${root_fs_dir}/lib/modules"
  if [[ ! -d "${root_fs_modules_path}" ]]; then
    return
  fi

  local kernel_path
  for kernel_path in "${root_fs_modules_path}/"*; do
    local kernel_release="$(basename ${kernel_path})"
    local kernel_out_dir="${board_root}/lib/modules/${kernel_release}/build"
    local system_map="${kernel_out_dir}/System.map"

    if [[ -r "${system_map}" ]]; then
      info_run sudo depmod -ae -F "${system_map}" -b "${root_fs_dir}" \
        "${kernel_release}"
    fi
  done
}

# Newer udev versions do not pay attention to individual *.hwdb files
# but require up to date /etc/udev/hwdb.bin. Let's [re]generate it as
# part of build process.
#
# Since hwdb is a generic "key/value database based on modalias strings"
# the version of udevadm found on the host should suffice.
run_udevadm_hwdb() {
  local root_fs_dir="$1"
  sudo udevadm hwdb --strict --update -r "${root_fs_dir}"
}
