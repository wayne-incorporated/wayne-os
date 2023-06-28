#!/bin/bash
# Copyright 2015 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Detect 32bit builds that are using legacy 32bit file interfaces.
# https://en.wikipedia.org/wiki/Large_file_support

# Lists gleaned from headers and this doc:
# http://people.redhat.com/berrange/notes/largefile.html
# http://opengroup.org/platform/lfs.html
SYMBOLS=(
  # aio.h
  aio_cancel
  aio_error
  aio_fsync
  aio_read
  aio_return
  aio_suspend
  aio_write
  lio_listio

  # dirent.h
  alphasort
  getdirentries
  readdir
  readdir_r
  scandir
  scandirat
  versionsort

  # fcntl.h
  creat
  fallocate
  fopen
  fopenat
  freopen
  open
  openat
  posix_fadvise
  posix_fallocate
  __open
  __open_2
  __openat_2

  # ftw.h
  ftw
  nftw

  # glob.h
  glob
  globfree

  # stdio.h
  fgetpos
  fopen
  freopen
  fseeko
  fsetpos
  ftello
  tmpfile

  # stdlib.h
  mkostemp
  mkostemps
  mkstemp
  mkstemps

  # sys/mman.h
  mmap

  # sys/resource.h
  getrlimit
  prlimit
  setrlimit

  # sys/sendfile.h
  sendfile

  # sys/stat.h
  fstat
  fstatat
  lstat
  stat
  __fxstat
  __fxstatat
  __lxstat
  __xstat

  # sys/statfs.h
  fstatfs

  # sys/statvfs.h
  statvfs
  fstatvfs

  # unistd.h
  lockf
  lseek
  ftruncate
  pread
  preadv
  pwrite
  pwritev
  truncate
  __pread_chk
)
SYMBOLS_REGEX=$(printf '%s|' "${SYMBOLS[@]}")
SYMBOLS_REGEX="^(${SYMBOLS_REGEX%|})$"

check_lfs()
{
  local files=$(scanelf -F '%s %p' -qRgs "-${SYMBOLS_REGEX}" "$@")

  if [[ -n ${files} ]]; then
    echo
    eqawarn "QA Notice: The following files were not built with LFS support:"
    eqawarn "  Please see http://crbug.com/464024 for details."
    eqawarn "${files}"
    echo
  fi
}

# Only check on 32bit systems.  Filtering by $ARCH here isn't perfect, but it
# should be good enough for our needs so far.
case ${ARCH} in
arm|mips|ppc|sh|x86)
  if [[ " ${RESTRICT} " == *" binchecks "* ]] ; then
    check_lfs "${D}"
  fi
  ;;
esac

# Allow for people to run manually for testing/debugging.
if [[ $# -ne 0 ]]; then
  eqawarn() { echo " * $*"; }
  check_lfs "$@"
fi
