#!/bin/bash

# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script looks for old perl modules inside the chroot and updates them.
# It is used by update_chroot and make_chroot.sh.
#
# Usage: simply run `perl_rebuild.sh` inside chroot without any argument.

SCRIPT_ROOT="$(readlink -f "$(dirname "$0")/..")"
# shellcheck source=../common.sh
. "${SCRIPT_ROOT}/common.sh" || exit 1

perl_rebuild() {
  # If the user still has old perl modules installed, update them.
  local perl_versions=$(find /usr/lib*/perl5/vendor_perl/ \
    -maxdepth 1 -mindepth 1 -type d -printf '%P\n' | sort -u | wc -w)
  if [[ "${perl_versions}" -gt 1 ]]; then
    # Some perl packages might not exist anymore due to the upgrade, so unmerge
    # any that no longer exist.
    info "Looking for outdated perl packages"
    local pkgs=()
    for pkg in $(qlist -IC dev-perl/ perl-core/ virtual/perl-); do
      equery which ${pkg} >/dev/null || pkgs+=( "${pkg}" )
    done
    if [[ ${#pkgs[@]} -gt 0 ]]; then
      sudo qmerge -Uyq "${pkgs[@]}"
    fi
    sudo perl-cleaner --all -- --quiet
    sudo find /usr/lib*/perl5/vendor_perl -type d -empty -delete
  fi
}

[[ $# -eq 0 ]] || die "No argument should be provided."

# Script must run inside the chroot
assert_inside_chroot "$@"

perl_rebuild "$@"
