#!/bin/sh
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This file defines the functions designated for Ti50 devices. The functions are
# then used in the shared GSC scripts.

gsc_name() {
  printf "ti50"
}

gsc_image_base_name() {
  printf "/opt/google/ti50/firmware/ti50.bin"
}

gsc_metrics_prefix() {
  printf "Platform.Ti50"
}

gsctool_cmd() {
  /usr/sbin/gsctool -D "$@"
}
