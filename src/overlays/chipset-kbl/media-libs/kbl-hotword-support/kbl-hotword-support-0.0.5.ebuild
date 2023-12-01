# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit cros-binary

DESCRIPTION="Kaby Lake hotword DSP firmware and language models"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tbz2"
LICENSE="Google-TOS"
SLOT="0"

KEYWORDS="-* x86 amd64"

S=${WORKDIR}

src_install() {
	insinto /
	doins -r *
}
