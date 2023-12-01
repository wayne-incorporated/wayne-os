# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

DESCRIPTION="MT8195 SOF topology"
SRC_URI="gs://chromeos-localmirror/distfiles/sof-topology-cherry-${PV}.tar.gz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"
BDEPEND=""

S=${WORKDIR}/${PN}-cherry-${PV}

src_install() {
	insinto /lib/firmware/mediatek/sof-tplg
	doins sof-mt8195-mt6359-rt1019-rt5682.tplg
	doins sof-mt8195-mt6359-max98390-rt5682.tplg
	dodoc README
}
