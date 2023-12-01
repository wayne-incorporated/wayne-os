# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

inherit toolchain-funcs

DESCRIPTION="Melfas Touchscreen HID-USB Tools for Firmware Update"
HOMEPAGE="https://github.com/melfas/mfs-console-tool"
SRC_URI="https://github.com/melfas/mfs-console-tool/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="virtual/libusb:1=
	virtual/libudev:="

RDEPEND="${DEPEND}"

src_configure() {
	tc-export CC CXX PKG_CONFIG
}

src_install() {
	dosbin melfas_update_tool
}
