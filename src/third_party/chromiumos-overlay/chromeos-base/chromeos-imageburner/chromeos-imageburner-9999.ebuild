# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk image-burner .gn"

PLATFORM_NATIVE_TEST="yes"
PLATFORM_SUBDIR="image-burner"

inherit cros-workon platform user

DESCRIPTION="Image-burning service for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/image-burner/"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
IUSE="user_session_isolation"

RDEPEND="
	sys-apps/rootdev
"
DEPEND="${RDEPEND}
	chromeos-base/system_api
"

pkg_preinst() {
	# Create user and group for image-burner.
	enewuser "image-burner"
	enewgroup "image-burner"
}

src_install() {
	platform_src_install

	# TODO(crbug/766130): Remove the following sed block when non-root mount
	# namespace is by default enabled.
	# Remove the env var value related to mount namespace if USE flag
	# user_session_isolation is not present.
	if ! use user_session_isolation; then
		sed -i -e "/env MNT_NS_ARGS=/s:=.*:=:" \
			"${D}"/etc/init/image-burner.conf || die
	fi
}

platform_pkg_test() {
	platform test_all
}
