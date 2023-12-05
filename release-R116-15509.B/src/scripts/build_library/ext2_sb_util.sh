#!/bin/bash
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# These two helpers clobber the ro compat value in our root filesystem.
#
# When the system is built with --enable_rootfs_verification, bit-precise
# integrity checking is performed.  That precision poses a usability issue on
# systems that automount partitions with recognizable filesystems, such as
# ext2/3/4.  When the filesystem is mounted 'rw', ext2 metadata will be
# automatically updated even if no other writes are performed to the
# filesystem.  In addition, ext2+ does not support a "read-only" flag for a
# given filesystem.  That said, forward and backward compatibility of
# filesystem features are supported by tracking if a new feature breaks r/w or
# just write compatibility.  We abuse the read-only compatibility flag[1] in
# the filesystem header by setting the high order byte (le) to FF.  This tells
# the kernel that features R24-R31 are all enabled.  Since those features are
# undefined on all ext-based filesystem, all standard kernels will refuse to
# mount the filesystem as read-write -- only read-only[2].
#
# [1] 32-bit flag we are modifying:
#  https://chromium.googlesource.com/chromiumos/third_party/kernel.git/+/HEAD/include/linux/ext2_fs.h#l417
# [2] Mount behavior is enforced here:
#  https://chromium.googlesource.com/chromiumos/third_party/kernel.git/+/HEAD/ext2/super.c#l857
#
# N.B., if the high order feature bits are used in the future, we will need to
#       revisit this technique.
disable_rw_mount() {
  local rootfs=$1
  local offset="${2-0}"  # in bytes
  local ro_compat_offset=$((0x464 + 3))  # Set 'highest' byte
  is_ext_filesystem "${rootfs}" "${offset}" || return 0
  is_ext2_rw_mount_enabled "${rootfs}" "${offset}" || return 0

  make_block_device_rw "${rootfs}"
  printf '\377' |
    sudo dd of="${rootfs}" seek=$((offset + ro_compat_offset)) \
      conv=notrunc count=1 bs=1 status=none
  # Force all of the file writes to complete, in case it's necessary for
  # crbug.com/954188
  sync
}

enable_rw_mount() {
  local rootfs=$1
  local offset="${2-0}"
  local ro_compat_offset=$((0x464 + 3))  # Set 'highest' byte
  is_ext_filesystem "${rootfs}" "${offset}" || return 0
  is_ext2_rw_mount_enabled "${rootfs}" "${offset}" && return 0

  make_block_device_rw "${rootfs}"
  printf '\000' |
    sudo dd of="${rootfs}" seek=$((offset + ro_compat_offset)) \
      conv=notrunc count=1 bs=1 status=none
  # Force all of the file writes to complete, in case it's necessary for
  # crbug.com/954188
  sync
}

is_ext2_rw_mount_enabled() {
  local rootfs=$1
  local offset="${2-0}"
  local ro_compat_offset=$((0x464 + 3))  # Get 'highest' byte
  local ro_compat_flag=$(sudo dd if="${rootfs}" \
    skip=$((offset + ro_compat_offset)) bs=1 count=1  status=none \
    2>/dev/null | hexdump -e '1 "%.2x"')
  test "${ro_compat_flag}" = "00"
}

# Returns whether the passed rootfs is an extended filesystem by checking the
# ext2 s_magic field in the superblock.
is_ext_filesystem() {
  local rootfs=$1
  local offset="${2-0}"
  local ext_magic_offset=$((0x400 + 56))
  local ext_magic=$(sudo dd if="${rootfs}" \
    skip=$((offset + ext_magic_offset)) bs=1 count=2 2>/dev/null |
    hexdump -e '1/2 "%.4x"')
  test "${ext_magic}" = "ef53"
}

# If the passed argument is a block device, ensure it is writtable and make it
# writtable if not.
make_block_device_rw() {
  local block_dev="$1"
  [[ -b "${block_dev}" ]] || return 0
  if [[ $(sudo blockdev --getro "${block_dev}") == "1" ]]; then
    sudo blockdev --setrw "${block_dev}"
  fi
}
