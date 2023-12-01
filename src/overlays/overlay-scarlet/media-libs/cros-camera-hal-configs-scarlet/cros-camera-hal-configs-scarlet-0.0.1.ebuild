# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

KEYWORDS="-* arm arm64"

DESCRIPTION="Chrome OS camera HAL config files for Scarlet"

LICENSE="Apache-2.0"
SLOT="0"

RDEPEND="!media-libs/arc-camera3-hal-configs-scarlet"

S="${WORKDIR}"

src_install() {
	insinto /etc/camera
	doins "${FILESDIR}"/camera3_profiles.xml
	doins "${FILESDIR}"/gcss/*.xml

	insinto /etc/camera/rkisp1
	doins "${FILESDIR}"/IQ/*.xml
}
