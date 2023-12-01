# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_pre_src_prepare_enable_cxx_exceptions() {
	cros_enable_cxx_exceptions
}

# Exclude /usr/share/vala containing .vapi files unused in Chromium
# OS. net-libs/libproxy ebuild installs these unconditionally and
# change upstream for this was rejected on https://bugs.gentoo.org/677886
PKG_INSTALL_MASK+=" /usr/share/vala/"
INSTALL_MASK+=" /usr/share/vala/"
