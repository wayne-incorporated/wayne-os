# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"
inherit toolchain-funcs

DESCRIPTION="Yet Another V4L2 Test Application"
HOMEPAGE="http://git.ideasonboard.org/yavta.git"
SRC_URI="http://storage.googleapis.com/chromeos-localmirror/distfiles/yavta-20181204.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}/${PN}"

src_compile() {
	emake CROSS_COMPILE="${CHOST}-" CFLAGS="${CFLAGS} -Iinclude"
}

src_install() {
	dobin yavta
}
