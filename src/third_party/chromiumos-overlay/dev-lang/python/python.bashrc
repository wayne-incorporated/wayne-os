# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Building python with sanitizer flags breaks asan builds,
# https://crbug.com/101030.
cros_pre_src_prepare_filter_sanitizers() {
	filter_sanitizers
}
