# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Alderlake hotword DSP language models"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.bz2"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* x86 amd64"

src_install() {
	insinto /opt/google/tgl-hotword-support
	doins ./*.bin
}
