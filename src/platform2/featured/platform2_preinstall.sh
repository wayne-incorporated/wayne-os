#!/bin/bash

# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

OUT=$1
VER=$2
sed -e "s/@BSLOT@/${VER}/g" \
  libfeatures.pc.in > "${OUT}/lib/libfeatures.pc"
sed -e "s/@BSLOT@/${VER}/g" \
  libfeatures_c.pc.in > "${OUT}/lib/libfeatures_c.pc"
