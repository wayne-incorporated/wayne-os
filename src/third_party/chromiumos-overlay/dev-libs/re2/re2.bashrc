# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# re2 is hot; optimize it for speed.
cros_pre_src_configure_mark_as_hot() {
	cros_optimize_package_for_speed
}
