# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# shellcheck source=../common.sh
. "${BUILD_LIBRARY_DIR}/../common.sh" || exit 1

# Usage: fs_parse_option <mount_options> <option_key> [default_value]
#
# Print the value associated with the option_key in the passed mount_options,
# or the optional default_value if it wasn't specified.
#
# Args:
#   mount_options: Options that could be passed to the "mount" command, for
#       example "loop,ro".
#   option_key: The key you are looking for.
#   default_value: An optional default value used if the option key is not
#       found.
fs_parse_option() {
  local mount_options="$1"
  local option_key="$2"
  local default_value="${3:-}"

  # offset= interacts with dirty pages in the file in a very poor manner.  See
  # crbug.com/954188. Use device partitions on the loop device instead.
  case "${option_key}" in
  offset|size)
    local msg="Support for ${option_key} dropped from fs_parse_option."
    msg="${msg} See crbug.com/954188."
    die "${msg}"
    # unittests cause die to return to us, so make sure we return the default.
    option_key='$'
    ;;
  esac

  local option_value
  if option_value=$(echo "${mount_options}" | tr , '\n' | \
      grep -E "^${option_key}"'(=|$)'); then
    echo "${option_value}" | cut --fields=2 --delimiter== --only-delimited
  else
    echo "${default_value}"
  fi
}

# Usage: fs_mount <part_dev> <mount_point> <fs_format> [ro_rw] [mount_options]
#
# Mount the passed partition device in the mount point. The partition is mounted
# as the fs_format filesystem (if fs_format is not empty). If the filesystem
# doesn't support to be mounted as read-write, like for example squashfs or
# ubifs, and "rw" mount is requested the contents are copied instead. When
# unmounted, the contents will be copied back to the partition, but you need to
# unmount the filesystem calling fs_umount.
#
# Args:
#   part_dev: A block device with the partition to mount.
#   mount_point: A directory where to mount the filesystem.
#   fs_format: The filesystem format, such as for example "ext2" or "squashfs".
#   ro_rw: The ro_rw parameter should be "ro" or "rw" (the default if empty).
#   mount_options: Extra mount options passed to the command "mount" when used.
fs_mount() {
  local part_dev="$1"
  local mount_point="$2"
  local fs_format="$3"
  local ro_rw="${4:-rw}"
  local mount_options="${5:-}"

  if [[ "${ro_rw}" != "ro" && "${ro_rw}" != "rw" ]]; then
    die "ro_rw must be \"ro\" or \"rw\", not \"${ro_rw}\"."
  fi

  # Explicitly deny offset= in options.
  if echo ${mount_options} | grep -qE '^(.*,)?offset='; then
    die "Support for offset= dropped from fs_mount.  See crbug.com/954188."
  fi

  local all_options="${ro_rw}"
  [[ -n "${mount_options}" ]] && all_options="${ro_rw},${mount_options}"

  # TODO: move this to layout file.(crbug.com/710929)
  case ${fs_format} in
  btrfs) all_options+=",compress=zlib";;
  esac

  case ${fs_format} in
  ext[234]|fat12|fat16|fat32|fat|vfat|btrfs|"")
    local extra_flags=()
    if [[ -n "${fs_format}" ]]; then
      case ${fs_format} in
      fat12|fat16|fat32|fat|vfat)
        extra_flags=( -t "vfat" )
        ;;
      *)
        extra_flags=( -t "${fs_format}" )
        ;;
      esac
    fi
    sudo mount "${part_dev}" "${mount_point}" -o "${all_options}" \
        "${extra_flags[@]}"
    ;;
  squashfs)
    if [[ "${ro_rw}" == "ro" ]]; then
      sudo mount "${part_dev}" "${mount_point}" -o "${all_options}" \
          -t "${fs_format}"
    else
      local sizelimit=$(fs_parse_option "${mount_options}" sizelimit)
      if [[ -n "${sizelimit}" ]]; then
        local losetup_opts=( --show --read-only --sizelimit "${sizelimit}" )
        part_dev=$(sudo losetup "${losetup_opts[@]}" -f "${part_dev}")
      fi

      sudo unsquashfs -dest "${mount_point}" -no-progress -force "${part_dev}"

      if [[ -n "${sizelimit}" ]]; then
        # Cleanup the loop device used to unsquash the filesystem.
        sudo losetup -d "${part_dev}"
      fi
      sudo unsquashfs -dest "${mount_point}" -no-progress -force "${part_dev}"
    fi
    ;;
  *)
    die "Unknown fs format '${fs_format}'";;
  esac
}

# Usage: fs_create <fs_uuid> <fs_label> <fs_bytes> <fs_block_size> <fs_format>
# <fs_options> <part_dev>
fs_create() {
  local fs_uuid="$1"
  local fs_label="$2"
  local fs_bytes=$3
  local fs_block_size=$4
  local fs_format="$5"
  local fs_options="$6"
  local part_dev="$7"

  # Split the fs_options into an array.
  local fs_options_arr=(${fs_options})

  case ${fs_format} in
  ext[234])
    # When mke2fs supports the same values for -U as tune2fs does, the
    # following conditionals can be removed and ${fs_uuid} can be used
    # as the value of the -U option as-is.
    local uuid_option=()
    if [[ "${fs_uuid}" == "clear" ]]; then
      fs_uuid="00000000-0000-0000-0000-000000000000"
    fi
    if [[ "${fs_uuid}" != "random" ]]; then
      uuid_option=( -U "${fs_uuid}" )
    fi
    sudo mkfs.${fs_format} -F -q -O ext_attr \
        "${uuid_option[@]}" \
        -E lazy_itable_init=0 \
        -b ${fs_block_size} \
        "${fs_options_arr[@]}" \
        "${part_dev}" "$((fs_bytes / fs_block_size))"
    # We need to redirect from stdin and clear the prompt variable to make
    # sure tune2fs doesn't throw up random prompts on us.  We know that the
    # command below is what we want and is safe (it's a new FS).
    unset TUNE2FS_FORCE_PROMPT
    sudo tune2fs -L "${fs_label}" \
        -c 0 \
        -i 0 \
        -T 20091119110000 \
        -m 0 \
        -r 0 \
        -e remount-ro \
        "${part_dev}" </dev/null
    ;;
  fat12|fat16|fat32)
    sudo mkfs.vfat -F ${fs_format#fat} -n "${fs_label}" "${part_dev}" \
        "${fs_options_arr[@]}"
    ;;
  fat|vfat)
    # -I flag is needed to ignore a (we think) false error about formatting
    # a device that already has partitions on it
    sudo mkfs.vfat -I -n "${fs_label}" "${part_dev}" "${fs_options_arr[@]}"
    ;;
  squashfs)
    # Creates an empty squashfs filesystem so unsquashfs works.
    local squash_dir="$(mktemp -d --suffix=.squashfs)"
    local squash_file="$(mktemp --suffix=.squashfs)"
    # Make sure / has the right permission. "-all-root" will change the uid/gid.
    chmod 0755 "${squash_dir}"
    # If there are errors in mkquashfs they are sent to stderr, but in the
    # normal case a lot of useless information is sent to stdout.
    mksquashfs "${squash_dir}" "${squash_file}" -noappend -all-root \
        -no-progress -no-recovery "${fs_options_arr[@]}" >/dev/null
    rmdir "${squash_dir}"
    sudo dd if="${squash_file}" of="${part_dev}" bs=4096 status=none
    rm "${squash_file}"
    ;;
  btrfs)
    sudo mkfs.${fs_format} -b "$((fs_bytes))" -d single -m single -M \
      -L "${fs_label}" -O "${fs_options_arr[@]}" "${part_dev}"
    ;;
  *)
    die "Unknown fs format '${fs_format}' for part ${part_dev}";;
  esac
}

# Usage: fs_umount <part_dev> <mount_point> <fs_format> <fs_options> \
#   [mount_options]
#
# Unmount the partition mounted with fs_mount.
#
# Args:
#   part_dev: The block device with the partition that was mounted.
#   mount_point: The directory where the partition was mounted.
#   fs_format: The filesystem format, such as for example "ext2" or "squashfs".
#   fs_options: The options used when creating the filesystem. These options are
#       used when we need to recreate the fs.
#   mount_options: Extra mount options passed to the command "mount" when used.
#       Only the "offset=" options is considering while unmounting.
fs_umount() {
  local part_dev="$1"
  local mount_point="$2"
  local fs_format="$3"
  local fs_options="$4"
  local mount_options="${5:-}"

  if mountpoint -q "${mount_point}"; then
    # First use safe_umount_tree for the general case. This also unmounts
    # mount points created with "mount --bind" in the filesystem.
    safe_umount_tree "${mount_point}"
    return
  fi

  case ${fs_format} in
  ext[234]|fat12|fat16|fat32|fat|vfat|"")
    # Nothing else to do for these filesystems.
    ;;
  squashfs)
    # Unmount anything else that could be mounted in the filesystem before
    # re-squashing.
    safe_umount_tree "${mount_point}"

    # Re-squash the filesystem to a temporary file.
    local squash_file="$(mktemp --suffix=.squashfs)"
    local fs_options_arr=(${fs_options})
    # If there are errors in mkquashfs they are sent to stderr, but in the
    # normal case a lot of useless information is sent to stdout.
    sudo mksquashfs "${mount_point}" "${squash_file}" -noappend \
        -no-progress -no-recovery "${fs_options_arr[@]}" >/dev/null

    local sizelimit=$(fs_parse_option "${mount_options}" sizelimit)
    local squashed_size=$(stat -c%s "${squash_file}")

    if [[ -n "${sizelimit}" && "${sizelimit}" -lt "${squashed_size}" ]]; then
      sudo rm -f "${squash_file}"
      die "The squashfs filesystem mounted at ${mount_point} is "\
"${squashed_size} bytes but the sizelimit is ${sizelimit} bytes, about "\
"$(( (squashed_size - sizelimit) / 1024 )) KiB smaller. Please increase the "\
"size of your filesystem or remove some files from it."
    fi

    # mksquashfs pads the filesystem up to 4kB, but we can use a bigger block
    # size to improve speed.
    sudo dd if="${squash_file}" of="${part_dev}" bs=8M \
        oflag=seek_bytes conv=notrunc status=none
    sudo rm -f "${squash_file}"
    ;;
  *)
    die "Unknown fs format '${fs_format}'";;
  esac
}

# Usage: fs_remove_mountpoint <mount_point>
#
# fs_umount will unmount the filesystem but will keep the mount point
# directory. When using squashfs in rw mode, the contents of the filesystem
# will remain in the mount point directory.
# This function removes the mountpoint directory as long as it is not mounted.
# Returns whether it was successfully removed.
fs_remove_mountpoint() {
  local mount_point="$1"
  safe_umount_tree "${mount_point}" || return
  if ! mountpoint -q "${mount_point}"; then
    sudo rm -rf "${mount_point}"
  fi
}
