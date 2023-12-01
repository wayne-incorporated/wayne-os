# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="tgl tuning DRC/EQ Param"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tbz2"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* x86 amd64"

S="${WORKDIR}"

src_install() {
	insinto /opt/google/drc-eq/
	doins ./*.bin
}
