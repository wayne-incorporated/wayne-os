# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Topology binary files used to support/configure LPE Audio"
LICENSE="LICENCE.adsp_sst"
SLOT="0"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-eve-${PV}.tbz2"
KEYWORDS="-* x86 amd64"

RDEPEND="
	media-libs/kbl-tuning-support
	media-libs/kbl-dsm-param
"


src_install() {
	insinto /
	doins -r ./*
}
