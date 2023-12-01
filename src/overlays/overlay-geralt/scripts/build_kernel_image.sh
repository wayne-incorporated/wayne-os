#!/bin/bash

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# All kernel command line changes must update the security base lines in
# the signer.  It rejects any settings it does not recognize and breaks the
# build.  So any modify_kernel_command_line() function change here needs to be
# reflected in ensure_secure_kernelparams.config.

# See crrev.com/i/216896 as an example.

modify_kernel_command_line() {
  local cmdline="$1"

  # Print kernel log to TTY console.
  # A hack for early bring-up only, remove this when we don't need the kernel
  # log on boot.
  # Remove `console= ` to use the path from `stdout-path` defined in DT.
  cmdline="${cmdline/console= /}"
  # Add `earlycon`
  cmdline="${cmdline} earlycon"
}
