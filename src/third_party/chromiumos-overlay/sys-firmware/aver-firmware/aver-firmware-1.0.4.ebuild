# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="AVer firmware"

CAM520_FW_VER="0.0.0018.36"
CAM540_FW_VER="0.0.6002.96"
CAM340PLUS_FW_VER="0.0.1000.34"

CAM520_FW_NAME="aver-cam520"
CAM540_FW_NAME="aver-cam540"
CAM340PLUS_FW_NAME="aver-cam340plus"

SRC_URI="gs://chromeos-localmirror/distfiles/${CAM520_FW_NAME}-${CAM520_FW_VER}.tar.xz
	gs://chromeos-localmirror/distfiles/${CAM540_FW_NAME}-${CAM540_FW_VER}.tar.xz
	gs://chromeos-localmirror/distfiles/${CAM340PLUS_FW_NAME}-${CAM340PLUS_FW_VER}.tar.xz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"

RDEPEND="sys-apps/aver-updater"
DEPEND=""

S="${WORKDIR}"

src_install() {
	insinto /lib/firmware/aver

	doins "${CAM520_FW_NAME}-${CAM520_FW_VER}.dat"
	dosym "${CAM520_FW_NAME}-${CAM520_FW_VER}.dat" \
		"/lib/firmware/aver/${CAM520_FW_NAME}-latest.dat"

	doins "${CAM540_FW_NAME}-${CAM540_FW_VER}.dat"
	dosym "${CAM540_FW_NAME}-${CAM540_FW_VER}.dat" \
		"/lib/firmware/aver/${CAM540_FW_NAME}-latest.dat"

	doins "${CAM340PLUS_FW_NAME}-${CAM340PLUS_FW_VER}.dat"
	dosym "${CAM340PLUS_FW_NAME}-${CAM340PLUS_FW_VER}.dat" \
		"/lib/firmware/aver/${CAM340PLUS_FW_NAME}-latest.dat"
}
