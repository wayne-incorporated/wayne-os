# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# Fork from https://github.com/flying-elephant/wacom_source/

EAPI="5"

inherit toolchain-funcs

DESCRIPTION="Wacom EMR/AES flash for Firmware Update"
GIT_TAG="v${PV}"
HOMEPAGE="https://github.com/flying-elephant/wacom_source/"
MY_P="wacom_source-${PV}"
SRC_URI="https://github.com/flying-elephant/wacom_source/archive/${GIT_TAG}.tar.gz -> ${P}.tar.gz"
S="${WORKDIR}/${MY_P}/wacom_flash"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC
}

src_install() {
	dosbin wacom_flash
}
