# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit toolchain-funcs

DESCRIPTION="ELAN TouchPad Firmware Updater (HID-Interface)"
HOMEPAGE="https://github.com/jinglewu/etphidiap/"
SRC_URI="https://github.com/jinglewu/etphidiap/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

# Old name for this package.  Must block old revisions which would install
# the same files as this package.
RDEPEND="!<chromeos-base/etphidiap-1.1-r3"
DEPEND="!<chromeos-base/etphidiap-1.1-r3"

src_configure() {
	tc-export CC
}

src_install() {
	dosbin etphid_updater
}
