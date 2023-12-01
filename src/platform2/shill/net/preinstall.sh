#!/bin/bash

# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

OUT=$1
v=$2

deps=$(<"${OUT}"/gen/libshill-net-deps.txt)
sed \
  -e "s/@BSLOT@/${v}/g" \
  -e "s/@PRIVATE_PC@/${deps}/g" \
  "libshill-net.pc.in" > "${OUT}/lib/libshill-net.pc"

