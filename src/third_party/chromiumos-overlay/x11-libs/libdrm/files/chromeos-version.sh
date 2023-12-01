#!/bin/bash
#
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script has a very specific command to print the numerical version
# number for the third_party/libdrm library. Note the space after the ^.

grep -E "^  version : '[0-9]+\.[0-9]+\.[0-9]+',$" meson.build | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+"