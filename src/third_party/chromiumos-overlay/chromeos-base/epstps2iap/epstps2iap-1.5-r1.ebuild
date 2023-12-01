# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit toolchain-funcs

DESCRIPTION="ELAN Standalone Trackpoint Firmware Update"
GIT_TAG="v${PV}"
HOMEPAGE="https://github.com/jinglewu/epstps2iap/"
SRC_URI="https://github.com/jinglewu/epstps2iap/archive/${GIT_TAG}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC
}

src_install() {
	dosbin epstps2_updater
}
