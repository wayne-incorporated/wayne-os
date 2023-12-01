# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Rockchip 3A library binaries required by the Rockchip camera HAL"
SRC_URI="gs://chromeos-localmirror/distfiles/rockchip-isp1-3a-libs-bin-${PV}.tbz2"

LICENSE="LICENCE.rockchip"
SLOT="0"
KEYWORDS="-* arm arm64"

S="${WORKDIR}"

src_install() {
	dolib.so *.so*
}
