# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Don't install static builds on target.
if [[ $(cros_target) != "board_sysroot" ]]; then
	INSTALL_MASK+=" /usr/sbin/vpd_s"
	PKG_INSTALL_MASK+=" /usr/sbin/vpd_s"
fi
