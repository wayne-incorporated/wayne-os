# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Building readline with sanitizers break chrooting, https://crbug.com/843301.
cros_pre_src_prepare_filter_sanitizers() {
	filter_sanitizers
}
