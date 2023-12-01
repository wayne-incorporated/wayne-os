# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Build without sanitizers to avoid fuzzer builders breakage,
# https://crbug.com/1171526
cros_pre_src_prepare_filter_sanitizers() {
	filter_sanitizers
}
