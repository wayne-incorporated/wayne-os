#!/bin/sh

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cargo clippy --features ti50_onboard --all-targets -- -D warnings
cargo clippy --features cr50_onboard --all-targets -- -D warnings
