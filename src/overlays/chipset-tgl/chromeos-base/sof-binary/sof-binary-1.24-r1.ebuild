# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=5

DESCRIPTION="Tiger Lake SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-tgl-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	media-libs/tgl-drceq-param
	media-libs/tgl-dsm-param
	media-libs/tgl-hotword-support
"
DEPEND="${RDEPEND}"

S=${WORKDIR}/${PN}-tgl-${PV}

src_install() {
	insinto /lib/firmware/intel/sof/community
	doins sof-tgl.ri
	dodoc README
}
