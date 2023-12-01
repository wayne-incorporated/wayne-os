# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_pre_src_prepare_patches() {
	patch -p1 < "${BASHRC_FILESDIR}"/${PN}-1.3.4-sandbox.patch || die
	patch -p1 < "${BASHRC_FILESDIR}"/${PN}-1.3.4-sandbox-default.patch || die
	EXTRA_ECONF+=" --enable-forced-sandbox"
}
