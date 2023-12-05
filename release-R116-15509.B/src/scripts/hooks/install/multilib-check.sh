#!/bin/bash
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Try and catch bad multilib usage at install time.  This check isn't meant
# to be 100% comprehensive, but should catch most bad behavior to be useful.
# We are basically hardcoding policy that already exists in Gentoo profiles,
# but we don't currently care about supporting full flexibility as no CrOS
# device should be doing weird stuff.
#
# We're a bit limited when it comes to lib64 users like x86_64 & aarch64.
# On those systems, /lib/ and /usr/lib/ are OK for arch-independent files,
# most commonly things like /usr/lib/debug/.  So it's trickier to detect
# bad usage of that path vs good usage.
#
# Fortunately, most bad usage impacts 32-bit userlands because the sdk itself
# tends to be 64-bit (lib64), so this hook should still be effective.

# See whether the specified path exists in any form.
# We'll update the |paths| array variable in the parent scope.
bad_path_exists() {
  local subdir="$1"
  local basedir path ret=0
  for basedir in / /usr /usr/local; do
    path="${D}${basedir%/}/${subdir}"
    if [[ -L "${path}" || -d "${path}" ]]; then
      paths+=( "${path}" )
      ret=1
    fi
  done
  return ${ret}
}

# Main entry point for this hook.
check_multilib() {
  local paths=()

  case "${CATEGORY}/${PN}" in
    # Needs to install a 64-bit archive on arm32 builds.
    chromeos-base/google-breakpad) return ;;
  esac

  case ${ARCH} in
  arm|x86)
    if ! bad_path_exists "lib64"; then
      eerror "Bad lib64 usage detected:"
      find "${paths[@]}" -exec ls -ldh {} +
      eerror "This arch (${ARCH}) should never use 'lib64'."
      die "This package is installing into bad paths."
    fi
    ;;
  esac
}

check_multilib
