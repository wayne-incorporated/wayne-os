# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="MT8195 tuning DSM Param"
SRC_URI="
	gs://chromeos-localmirror/distfiles/dsm-param-dojo-${PV}.tar.bz2
"

LICENSE="LICENSE.dsm"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

src_install() {
	insinto /lib/firmware
	doins ./dsmparam/*.bin
}
