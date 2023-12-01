#!/bin/bash -eu
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script turns the directory it's run in into a pristine Rust checkout.
# It does this by wiping out all changes in $PWD and all submodules, and
# updating submodules to match the version that $PWD's HEAD expects.

git clean -fd
git reset --hard HEAD
git submodule foreach --recursive bash -c 'git clean -fd && git reset --hard HEAD'
git submodule update --recursive
