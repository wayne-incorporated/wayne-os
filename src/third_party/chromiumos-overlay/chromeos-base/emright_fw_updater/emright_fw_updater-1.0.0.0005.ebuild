# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

inherit toolchain-funcs

DESCRIPTION="EMRight Digitizer for Firmware Update"
HOMEPAGE="https://github.com/emright123/emright_fw_updater"
SRC_URI="https://github.com/emright123/emright_fw_updater/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CXX
}

src_install() {
	dosbin EMRight_FWupdate
}
