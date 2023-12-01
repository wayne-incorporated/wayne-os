# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO(crbug.com/1047552): Disable string-compare warning which causes build
# failure due to false positive warning case.
cros_pre_src_configure_dis_str_cmp() {
	append-flags -Wno-string-compare || die
}
