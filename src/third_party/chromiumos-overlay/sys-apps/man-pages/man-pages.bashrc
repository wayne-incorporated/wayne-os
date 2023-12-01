# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_post_src_install_license() {
	"${BASHRC_FILESDIR}"/extract-licenses.py -d "${S}" -o "${S}/LICENSE" || die
}
