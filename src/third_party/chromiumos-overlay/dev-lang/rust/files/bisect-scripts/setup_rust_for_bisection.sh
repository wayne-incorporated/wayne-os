#!/bin/bash -eu
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

my_dir="$(dirname "$(readlink -m "$0")")"
rust_dir="${my_dir}/../rust"

if [[ -e "${rust_dir}/.git" ]]; then
  echo "It seems that a Rust checkout at ${rust_dir} already exists. Skipping initial clone."
else
  # If any partially-formed (/empty) things are here, remove them.
  rm -rf "${rust_dir}"
  echo "Cloning a new Rust checkout at ${rust_dir} ..."
  git clone https://github.com/rust-lang/rust "${rust_dir}"
  git -C "${rust_dir}" submodule init
fi

echo "Cleaning + syncing Rust's root directory ..."
(cd "${rust_dir}" && "${my_dir}/clean_and_sync_rust_root.sh")

rust_eclass="${my_dir}/../../../../eclass/cros-rustc.eclass"
if grep -q '^CROS_RUSTC_BUILD_RAW_SOURCES=$' "${rust_eclass}"; then
  echo "Setting CROS_RUSTC_BUILD_RAW_SOURCES in ${rust_eclass} ..."
  sed -i 's/^CROS_RUSTC_BUILD_RAW_SOURCES=$/\01/' "${rust_eclass}"
else
  echo "CROS_RUSTC_BUILD_RAW_SOURCES is already set in ${rust_eclass}"
fi
