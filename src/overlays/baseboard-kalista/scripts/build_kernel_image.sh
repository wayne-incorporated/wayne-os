#!/bin/bash

# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

modify_kernel_command_line() {
  echo "disablevmx=off" >> "$1"

  # Enable l1d_flush for untrusted VM security
  echo "kvm-intel.vmentry_l1d_flush=always" >> "$1"
}
