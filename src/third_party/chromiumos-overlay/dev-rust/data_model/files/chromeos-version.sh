#!/bin/sh
#
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Assumes the first 'version =' line in the Cargo.toml is the version for the
# crate.
#
# 50 is added to the minor version number to avoid conflicting with a
# different copy included by path with the same version number.
awk '/^version = / {
  gsub(/"/, "", $0);
  split($3,ver,".");
  print ver[1] "." ver[2] "." (50 + ver[3]);
  exit
}' "$1/common/data_model/Cargo.toml"
