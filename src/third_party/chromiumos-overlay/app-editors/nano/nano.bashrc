# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# b/194140826: use icf=safe as nano gets mis-linked with icf=all.
cros_pre_src_configure_icf_safe() {
	replace-flags "-Wl,--icf=all" "-Wl,--icf=safe" || die
}
