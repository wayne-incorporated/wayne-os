# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="kbl tuning DSM Param"
SRC_URI="gs://chromeos-localmirror/distfiles/kbl-dsm-param-soraka-${PV}.tbz2"

LICENSE="LICENSE.dsm"
SLOT="0"
KEYWORDS="-* x86 amd64"

S="${WORKDIR}"

src_install() {
	insinto /opt/google/dsm
	doins dsmparam.bin
}
