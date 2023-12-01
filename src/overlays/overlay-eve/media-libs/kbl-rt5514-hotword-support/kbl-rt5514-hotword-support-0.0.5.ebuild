# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit cros-binary

DESCRIPTION="kbl rt5514 hotword DSP firmware and language models"
LICENSE="LICENCE.adsp_sst"		#FIXME: Need DSM license
SLOT="0"

KEYWORDS="*"

S=${WORKDIR}

SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tbz2"
src_install() {
	insinto /
	doins -r ./*
}
