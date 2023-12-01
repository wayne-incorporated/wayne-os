# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=5

DESCRIPTION="Gemini Lake SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-glk-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-glk-${PV}

src_install() {
	insinto /lib/firmware/intel/sof
	doins sof-glk.ri
	dodoc README
}
