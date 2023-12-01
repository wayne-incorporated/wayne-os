# shellcheck shell=bash
#
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Append lxd-next paths to PATH and LD_LIBRARY_PATH
#
# We have to do this both here and in maitred for three reasons:
#  1) vshd is started before the StartTermina RPC, so it's environment variables
#     don't reflect information about which LXD should be used
#  2) /etc/profile adds the "normal" PATH entries *before* existing PATH values,
#     whereas we need the lxd-next paths to come first, so even if vshd did have
#     a correct PATH the resulting login shell wouldn't.
#  3) vshd clears the environment before exec anyway
#
# This file is installed as a dot-file in /etc/bash/bashrc.d/ (which will be
# ignored) and bind-mounted over an empty file in the same directory if it is
# needed.

export PATH="/opt/google/lxd-next/bin:/opt/google/lxd-next/usr/bin:${PATH}"
export LD_LIBRARY_PATH="/opt/google/lxd-next/lib:/opt/google/lxd-next/lib64:/opt/google/lxd-next/usr/lib:/opt/google/lxd-next/usr/lib64:${LD_LIBRARY_PATH}"
