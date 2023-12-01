#!/bin/sh

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

sed -n 's/set(GOOGLETEST_VERSION\s\+\(.*\))/\1/p' "$1/CMakeLists.txt"