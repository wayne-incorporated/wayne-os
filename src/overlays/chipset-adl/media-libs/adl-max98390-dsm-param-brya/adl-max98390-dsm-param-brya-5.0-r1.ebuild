# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="ADL MAX98390 tuning DSM Param"
SRC_URI="
gs://chromeos-localmirror/distfiles/dsm-param-redrix-1.0.tar.bz2
gs://chromeos-localmirror/distfiles/dsm-param-gimble-2.0.tar.bz2
"

LICENSE="LICENSE.dsm"
SLOT="0"
KEYWORDS="-* x86 amd64"

S="${WORKDIR}"

src_install() {
	insinto /lib/firmware
	doins ./*.bin
}
