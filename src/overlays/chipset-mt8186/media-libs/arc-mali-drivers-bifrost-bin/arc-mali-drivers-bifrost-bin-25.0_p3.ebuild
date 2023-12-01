# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit unpacker

DESCRIPTION="ARC++ Mali Bifrost user space prebuilt binaries for external builds"
HOMEPAGE=""
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/arc-mali-drivers-bifrost-corsola-${PV}.run"

LICENSE="Google-TOS"
SLOT="0"
KEYWORDS="-* arm64 arm"

RDEPEND="
	>=x11-libs/libdrm-2.4.97
	!media-libs/arc-mali-drivers-bifrost
	!media-libs/arc-mesa
"

S=${WORKDIR}

src_install() {
	cp -pPR "${S}"/* "${D}/" || die "Install failed!"
}
