#!/bin/sh
#
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Assumes the first 'version =' line in the Cargo.toml is the version for the
# crate.
awk '/^version = / { print $3; exit }' "$1/resourced/Cargo.toml" | tr -d '"'
