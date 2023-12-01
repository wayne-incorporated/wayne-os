# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Tigerlake hotword DSP language models"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* x86 amd64"

src_install() {
	insinto /opt/google/tgl-hotword-support
	doins ./*.bin
}
