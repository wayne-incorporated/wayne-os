#!/bin/bash

# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# All kernel command line changes must update the security base lines in
# the signer.  It rejects any settings it does not recognize and breaks the
# build.  So any modify_kernel_command_line() function change here needs to be
# reflected in ensure_secure_kernelparams.config.

# See crrev.com/i/216896 as an example.

modify_kernel_command_line() {
	echo "amdgpu.abmlevel=0x4" >> "$1"

	# See b/189856884 - enable PSR
	echo "amdgpu.dcfeaturemask=0x8" >> "$1"

	# See b/218950907
	echo "rtc-cmos.use_acpi_alarm=1" >> "$1"

	# See b/219534576
	echo "amd-pmc.enable_stb=1" >> "$1"
}
