# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit unpacker

DESCRIPTION="Mali drivers, binary only install"
HOMEPAGE=""
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/mali-drivers-valhall-asurada-${PV}.run"

LICENSE="Google-TOS"
SLOT="0"
KEYWORDS="-* arm64 arm"

RDEPEND="
	>=x11-libs/libdrm-2.4.34
	!media-libs/mali-drivers-valhall
	!x11-drivers/opengles
	!media-libs/mesa
"

S=${WORKDIR}

src_install() {
	cp -pPR "${S}"/* "${D}/" || die "Install failed!"
}
