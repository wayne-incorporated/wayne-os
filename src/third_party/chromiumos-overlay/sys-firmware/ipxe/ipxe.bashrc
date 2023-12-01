# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# ipxe fails to build with clang, in the sdk
cros_pre_src_prepare_use_gcc() {
	cros_use_gcc
}
