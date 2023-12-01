#!/bin/bash -eu
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Prepares the current directory (assuming it's a rustc checkout) for an
# offline build by cros-rust.eclass' CROS_RUSTC_BUILD_RAW_SOURCES feature. This
# is done by:
# - Invoking x.py to download the bootstrap compiler
# - Running `cargo vendor` to move all dependencies into `vendor/`.

# Unset `SUDO_USER`; if it's set, `./x.py` will automatically try to use
# vendored sources.
unset SUDO_USER

# This always exits with an error; we scrape its output to ensure it DTRT.
echo "Ensuring the bootstrap compiler is downloaded; this can take a bit..."
xpy_help=$(./x.py --help 2>&1) || :
if ! grep -qF 'Usage: x.py <subcommand>' <<< "${xpy_help}"; then
  echo "${xpy_help}" >&2
  echo >&2
  echo "Running x.py --help to download bootstrap compilers failed. See stdout above." >&2
  exit 1
fi
cargo vendor
