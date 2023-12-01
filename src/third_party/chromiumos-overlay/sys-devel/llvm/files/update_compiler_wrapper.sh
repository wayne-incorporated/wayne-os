#!/bin/bash
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Copies the compiler wrapper sources from toolchain_utils
# into the local compiler_wrapper folder, including the `build.py`
# command to build the wrapper.

DIR=$(dirname "$0")
TOOLCHAIN_UTILS_DIR="${DIR}/../../../../toolchain-utils"
COMPILER_WRAPPER_DIR="${DIR}/compiler_wrapper"

"${TOOLCHAIN_UTILS_DIR}/compiler_wrapper/bundle.py" --output_dir "${COMPILER_WRAPPER_DIR}"
