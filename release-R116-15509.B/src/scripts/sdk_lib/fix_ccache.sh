#!/bin/bash

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to fix permissions on ccache tree.

SCRIPT_ROOT=$(readlink -f "$(dirname "$0")"/..)
# shellcheck source=../common.sh
. "${SCRIPT_ROOT}/common.sh" || exit 1

# Define command line flags
# See http://code.google.com/p/shflags/wiki/Documentation10x
DEFINE_string chroot "" "The destination dir for the chroot environment."

# Parse command line flags.
FLAGS_HELP="usage: ${SCRIPT_NAME} [flags]"
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

if [ -z "${FLAGS_chroot}" ]; then
  die "--chroot is required"
fi

# Walking ccache dir can be expensive, so only do it once, but make sure
# to run both sets of tests+execs independently.
ccache_dir="${FLAGS_chroot}/var/cache/distfiles/ccache"
find -H "${ccache_dir}" \
  '(' -type d -a '!' -perm 2775 ')' -exec chmod 2775 {} + \
  , \
  -gid 0 -exec chgrp 250 {} +

# These settings are kept in sync with the gcc ebuild.
chroot "${FLAGS_chroot}" env CCACHE_DIR=/var/cache/distfiles/ccache \
  CCACHE_UMASK=002 ccache -F 0 -M 11G >/dev/null
