# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

DESCRIPTION="Provide the Name Service Switch configuration file for glibc"
HOMEPAGE="http://www.chromium.org/"
LICENSE="BSD-Google"
SLOT="0"

KEYWORDS="*"

IUSE="zeroconf"

S=${WORKDIR}

RDEPEND="
	!<chromeos-base/shill-0.0.3
	zeroconf? ( sys-auth/nss-mdns )
"

src_install() {
	insinto /etc
	if use zeroconf; then
		newins "${FILESDIR}"/nsswitch.mdns.conf nsswitch.conf
	else
		newins "${FILESDIR}"/nsswitch.default.conf nsswitch.conf
	fi
}
