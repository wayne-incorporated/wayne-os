# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="adl tuning bandsplit EQIIR param for brya 2-way tplg"
SRC_URI="gs://chromeos-localmirror/distfiles/adl-bandsplit-eq-param-brya-${PV}.tbz2"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* x86 amd64"

S="${WORKDIR}"

src_install() {
	insinto /opt/google/bandsplit-eq/
	doins ./*.bin
}
