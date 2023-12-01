# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit eutils cros-sanitizers

DESCRIPTION="CUPS filter and PPD files for Star Micronics printers"
HOMEPAGE="http://www.starmicronics.com"
SRC_URI="http://www.starmicronics.com/support/DriverFolder/drvr/starcupsdrv-${PV}_linux.tar.gz -> starcupsdrv-${PV}_linux.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="net-print/cups:="
RDEPEND="${DEPEND}"

src_unpack() {
	default
	unpack ./${PN}-${PV%_*}_linux/SourceCode/starcupsdrv-src-${PV%_*}.tar.gz
	mv starcupsdrv starcupsdrv-${PV} || die
}

src_prepare() {
	epatch_user
}

src_configure() {
	sanitizers-setup-env
	default
}

src_install() {
	exeinto "$(${SYSROOT}/usr/bin/cups-config --serverbin)/filter"
	doexe install/rastertostar
	doexe install/rastertostarm
	doexe install/rastertostarlm
}
