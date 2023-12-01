# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_post_src_install_clear_caps() {
	setcap -r "${D}"/sbin/setcap
}
