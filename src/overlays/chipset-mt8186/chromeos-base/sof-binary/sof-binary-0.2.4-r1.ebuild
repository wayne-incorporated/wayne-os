# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

DESCRIPTION="MT8186 SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-mt8186-${PV}.tar.gz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"
BDEPEND=""

S=${WORKDIR}/${PN}-mt8186-${PV}

src_install() {
		insinto /lib/firmware/mediatek/sof
		doins sof-mt8186.ri
}
