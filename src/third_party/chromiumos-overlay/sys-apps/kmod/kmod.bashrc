# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_pre_src_prepare_patches() {
	patch -p1 < "${BASHRC_FILESDIR}"/${PN}-30-no-run.patch || die
	patch -p1 < "${BASHRC_FILESDIR}"/${PN}-30-pass-compressed-to-kernel.patch || die
}
