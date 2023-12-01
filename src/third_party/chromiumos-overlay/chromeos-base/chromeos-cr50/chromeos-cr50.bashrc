# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# We want to continue to use gcc to build firmware.  http://crbug.com/641388
cros_pre_src_prepare_use_gcc() {
	cros_use_gcc
}
