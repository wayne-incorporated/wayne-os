# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Disable alignement sanitization for snappy, https://crbug.com/1022899.
cros_pre_src_prepare_filter_sanitizers() {
	append-flags -fno-sanitize=alignment || die
}
