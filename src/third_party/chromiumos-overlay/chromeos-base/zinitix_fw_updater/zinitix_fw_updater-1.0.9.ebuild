# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
inherit toolchain-funcs

DESCRIPTION="Zinitix Digitizer for Firmware Update"
HOMEPAGE="https://github.com/zinitix-solution/zinitix_fw_updater"
SRC_URI="https://github.com/zinitix-solution/zinitix_fw_updater/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC
}

src_install() {
	dosbin Zinitix_FWupdate
}
