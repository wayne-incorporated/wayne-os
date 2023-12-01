#!/bin/bash

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

modify_kernel_command_line() {
  (
    echo "console=ttyS0"
    echo "crashkernel=128M"
    echo "loadpin.exclude=kexec-image"
  ) >> "$1"
}
