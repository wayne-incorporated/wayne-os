# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Chromeos SCP firmware payload for cherry."

RESTRICT="strip"
LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm arm64"

SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tbz2"

S=${WORKDIR}/${P}

src_install() {
	# For newer kernels we have subdirectories for each SoC
	insinto /lib/firmware/mediatek/mt8195/
	doins scp.img

	# Add a symlink to make it backward compatible for old kernels
	dosym mediatek/mt8195/scp.img /lib/firmware/scp.img
}
