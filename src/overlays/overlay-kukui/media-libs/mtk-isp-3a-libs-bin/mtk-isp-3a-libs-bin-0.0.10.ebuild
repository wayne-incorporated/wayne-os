# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit toolchain-funcs unpacker

DESCRIPTION="MediaTek 3A library binaries required by the MediaTek camera HAL"
SRC_URI="gs://chromeos-localmirror/distfiles/mtk-isp-3a-libs-bin-${PV}.tar.xz"

LICENSE="LICENCE.mediatek"
SLOT="0"
KEYWORDS="-* arm arm64"

S="${WORKDIR}"

src_install() {
	dolib.so mtk-isp-3a-libs-bin/*.so*
}
