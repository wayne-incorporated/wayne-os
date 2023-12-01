# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="kbl tuning DSM DSP firmware and library models"
SRC_URI="gs://chromeos-localmirror/distfiles/${PF}.tbz2"

LICENSE="LICENCE.adsp_sst"		#FIXME: Need DSM license
SLOT="0"
KEYWORDS="-* x86 amd64"

S=${WORKDIR}

src_install() {
	insinto /lib
	doins -r lib/*
}
