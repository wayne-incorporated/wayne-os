# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

DESCRIPTION="MT8186 SOF topology"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-staryu-${PV}.tar.gz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"
BDEPEND=""

S=${WORKDIR}/${PN}-staryu-${PV}

src_install() {
		insinto /lib/firmware/mediatek/sof-tplg
		doins sof-mt8186.tplg
}
