# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# If we install this package, make sure the lsb-release reflects us.
# https://crbug.com/789839
cros_post_src_install_rewrite_lsb_release() {
	cat <<EOF >"${D}"/etc/lsb-release
DISTRIB_CODENAME=ChromiumOS
DISTRIB_DESCRIPTION="The fast, simple, and secure OS for the web"
DISTRIB_ID=chromiumos
DISTRIB_RELEASE=rolling
EOF
}
