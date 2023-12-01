#!/bin/bash

# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

OUT=$1
VER=$2
sed -e "s/@BSLOT@/${VER}/g" \
  libchromeos-ui.pc.in > "${OUT}/lib/libchromeos-ui.pc"
