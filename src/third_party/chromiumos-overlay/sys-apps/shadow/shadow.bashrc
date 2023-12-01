# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PKG_INSTALL_MASK+=" /etc/pam.d/login"
INSTALL_MASK+=" /etc/pam.d/login"

cros_post_src_install_unset_suid() {
	# Remove suid bit from all binaries installed by the package.
	# Neither of them have any practical use in ChromiumOS, but they
	# do present security risk.
	find "${D}" -perm /4000 -exec chmod -s {} +
}

cros_pre_pkg_postinst_disable() {
	# pkg_postinst() in upstream package will try to run grpconf thus
	# splitting /etc/group into group and gshadow. Don't let it do that.
	unset -f pkg_postinst
}
