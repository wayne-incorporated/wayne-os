# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
inherit toolchain-funcs

DESCRIPTION="Novatek Touch Firmware Update"
HOMEPAGE="https://github.com/Novatek-MSP/chromeos-nvt-touch-updater"
SRC_URI="https://github.com/Novatek-MSP/chromeos-nvt-touch-updater/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC
}

src_install() {
	dosbin NT36523_Cmd_HID_I2C
	dosbin Bdg_Cmd_M252
}
