# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

inherit toolchain-funcs

DESCRIPTION="Goodix HIDRAW Firmware Update Tool"
GIT_TAG="v${PV}"
HOMEPAGE="https://github.com/goodix/gdix_hid_firmware_update"
SRC_URI="https://github.com/goodix/gdix_hid_firmware_update/archive/${GIT_TAG}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CXX
}

src_install() {
	dosbin gdixupdate
}
