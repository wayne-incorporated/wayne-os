# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

inherit toolchain-funcs

DESCRIPTION="G2touch touchscreen firmware update tool"
HOMEPAGE="https://github.com/g2touch/g2update_tool"
SRC_URI="https://github.com/g2touch/g2update_tool/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC CXX
}

src_install() {
	dosbin bin/g2fwcheck
	dosbin bin/g2updater
}
