# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="Install per-board hardware features for ARC++."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
S="${WORKDIR}"

src_install() {
	insinto /etc
	doins "${FILESDIR}/hardware_features.xml"

	# Install and rename the script for ArcSetup.
	dosbin "${FILESDIR}/board_hardware_features.sh"
	mv "${D}/usr/sbin/board_hardware_features.sh" \
		"${D}/usr/sbin/board_hardware_features"
}
