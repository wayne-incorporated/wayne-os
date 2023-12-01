# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=4

inherit unpacker

DESCRIPTION="Mali drivers, binary only install"
HOMEPAGE=""
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/mali-drivers-arm64-${PVR}.run"

LICENSE="Google-TOS"
SLOT="0"
KEYWORDS="-* arm64 arm"

DEPEND="
	x11-drivers/opengles-headers
	"

RDEPEND="
	!media-libs/mali-drivers
	!x11-drivers/opengles
	x11-libs/libdrm
	"

S=${WORKDIR}

src_install() {
	cp -pPR "${S}"/* "${D}/" || die "Install failed!"
}
