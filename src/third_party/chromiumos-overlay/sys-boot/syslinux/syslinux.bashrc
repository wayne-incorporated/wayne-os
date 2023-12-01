# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# syslinux cannot be built from clang. See https://crbug.com/475978
cros_pre_src_prepare_use_gcc() {
	cros_use_gcc
}
