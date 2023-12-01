#!/bin/bash

# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# USAGE
# Download android-sdk from ab/aosp-sdk-release and expand.
# First Argument: path to the expanded android-sdk
# Second Argument: path to the lisence file ex) licenses/AOSP-SDK

source_dir=$1
target_file=$2

set -o pipefail

# Combine license files in the directories which we install.
find "${source_dir}"/platforms/ "${source_dir}"/build-tools/ '(' -name 'NOTICE*' -o -name '*LICENSE*' ')' -print0 | \
  xargs -0 sha256sum | \
  sort | \
  uniq -w 64 | \
  cut -b67- | \
  sort -z | \
  xargs -d'\n' cat > "${target_file}"
