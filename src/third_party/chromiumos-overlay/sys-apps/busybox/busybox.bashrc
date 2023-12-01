# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Builing busybox with llvm fails recovery image. https://crosbug.com/650227
# and https://crosbug.com/p/58976
cros_pre_src_prepare_use_gcc() {
	cros_use_gcc
}
