# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

MY_P="wireless-regdb-${PV:0:4}.${PV:4:2}.${PV:6:2}"
DESCRIPTION="Binary regulatory database for CRDA"
HOMEPAGE="https://wireless.wiki.kernel.org/en/developers/regulatory/wireless-regdb"
SRC_URI="https://www.kernel.org/pub/software/network/${PN}/${MY_P}.tar.xz"
S="${WORKDIR}/${MY_P}"

LICENSE="ISC"
SLOT="0"
KEYWORDS="*"

PATCHES=(
	"${FILESDIR}"/regdb-ar-5ghz.patch
	"${FILESDIR}"/regdb-Ensure-outfile-is-written.patch
)

src_compile() {
	emake -j1 REGDB_AUTHOR=chromium
}

src_install() {
	# This file is not ABI-specific, and crda itself always hardcodes
	# this path.  So install into a common location for all ABIs to use.
	insinto /usr/lib/crda
	doins regulatory.bin

	insinto /usr/lib/crda/pubkeys
	doins chromium.key.pub.pem

	# Linux 4.15 now complains if the firmware loader
	# can't find these files #643520
	insinto /lib/firmware
	doins regulatory.db
	doins regulatory.db.p7s

	doman regulatory.bin.5
	dodoc README db.txt
}
