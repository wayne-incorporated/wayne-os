# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="kbl tuning DSM Param"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-eve-${PV}.tbz2"

LICENSE="LICENCE.adsp_sst"		#FIXME: Need DSM license
SLOT="0"
KEYWORDS="-* x86 amd64"

src_install() {
	insinto /
	doins -r ./*
}
