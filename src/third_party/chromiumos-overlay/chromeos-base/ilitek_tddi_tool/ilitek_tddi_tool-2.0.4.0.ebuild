# Copyright 2023 The Chromium OS Authors. All rights reserved.
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
inherit toolchain-funcs

DESCRIPTION="Ilitek TDDI Touchscreen Tool for Firmware Update"
HOMEPAGE="https://github.com/ILITEK-LoganLin/ilitek_tddi_tool"
SRC_URI="https://github.com/ILITEK-LoganLin/ilitek_tddi_tool/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC
}

src_install() {
	dosbin ilitek_tddi
}
