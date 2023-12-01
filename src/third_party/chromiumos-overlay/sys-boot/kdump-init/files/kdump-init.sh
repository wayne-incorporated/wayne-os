#!/bin/sh
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# kdump-image is a symbolic link to the kernel image used by kexec.
# On arm this is a link to Image, and on X86 a link to vmlinuz.
# The kernel image contains a ramdisk doing all the kdump logic.
KDUMP_IMAGE=/usr/share/kdump/boot/kdump-image

kexec-lite -a LoadCrash -c "$(cat /proc/cmdline)" -k "${KDUMP_IMAGE}"

sysctl -w kernel.kexec_load_disabled=1
