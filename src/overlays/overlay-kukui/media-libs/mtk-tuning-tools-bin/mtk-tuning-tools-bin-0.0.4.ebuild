# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit toolchain-funcs unpacker

DESCRIPTION="MediaTek tuning tools binaries required by the MediaTek camera HAL"
SRC_URI="gs://chromeos-localmirror/distfiles/mtk-tuning-tools-bin-${PV}.tar.xz"

LICENSE="LICENCE.mediatek"
SLOT="0"
KEYWORDS="-* arm arm64"

S="${WORKDIR}"

src_install() {
	dolib.so mtk-tuning-tools-bin/*.so*
	dobin mtk-tuning-tools-bin/adbd
	dobin mtk-tuning-tools-bin/start-adb.sh
	dobin mtk-tuning-tools-bin/start-adb-2.sh
	dobin mtk-tuning-tools-bin/camtool
	dobin mtk-tuning-tools-bin/jpegtool
	dobin mtk-tuning-tools-bin/cct_camera
	dobin mtk-tuning-tools-bin/cct_camera_server
	dobin mtk-tuning-tools-bin/cct_camera_cmd
}
