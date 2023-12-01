# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit unpacker

DESCRIPTION="PowerVR Rogue GLES2 hardware driver, binary only install"
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/img-ddk-oak-${PVR}.run"

LICENSE="Google-TOS"
SLOT="0"
KEYWORDS="-* arm"

RDEPEND="
	!media-libs/img-ddk
	x11-libs/libdrm
	"

S=${WORKDIR}

src_install() {
	cp -pPR "${S}"/* "${D}/" || die "Install failed!"
}
