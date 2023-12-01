# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Runtime configuration file for fakemodem (autotest dep)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

src_install() {
	insinto /etc/dbus-1/system.d
	doins "${FILESDIR}/org.chromium.FakeModem.conf"
}
