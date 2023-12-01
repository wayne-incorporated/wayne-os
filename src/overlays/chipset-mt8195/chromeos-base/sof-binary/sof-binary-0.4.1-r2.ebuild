# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

DESCRIPTION="MT8195 SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/sof-binary-mt8195-${PV}.tar.gz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND=""
RDEPEND="
	media-libs/mt8195-dsm-param
"
BDEPEND=""

S=${WORKDIR}/${PN}-mt8195-${PV}

src_install() {
	insinto /lib/firmware/mediatek/sof
	doins sof-mt8195.ri
	doins sof-mt8195.ldc
	dodoc README
}
