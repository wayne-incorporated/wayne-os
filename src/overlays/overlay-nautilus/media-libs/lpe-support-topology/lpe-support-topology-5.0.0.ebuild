# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Topology binary files used to support/configure LPE Audio"
LICENSE="LICENCE.adsp_sst"
SLOT="0"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-nautilus-${PV}.tbz2"
KEYWORDS="-* x86 amd64"

RDEPEND="
	media-libs/kbl-hotword-support
"
DEPEND="${RDEPEND}"

S=${WORKDIR}

src_install() {
	cd ${P}
	insinto /
	doins -r *
}
