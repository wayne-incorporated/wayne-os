# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# spirv-tools fails to build with sanitizer flags, https://crbug.com/943766.
cros_pre_src_prepare_filter_sanitizers() {
	filter_sanitizers
}
