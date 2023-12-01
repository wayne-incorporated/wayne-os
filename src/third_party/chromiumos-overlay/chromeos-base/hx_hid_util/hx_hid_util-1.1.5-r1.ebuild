# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit toolchain-funcs

DESCRIPTION="Himax I2C-HID Utility for Firmware Update"
GIT_TAG="V${PV}"
HOMEPAGE="https://github.com/HimaxSoftware/hx_hid_util"
SRC_URI="https://github.com/HimaxSoftware/hx_hid_util/archive/${GIT_TAG}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CXX
}

src_install() {
	dosbin hx_util
}
