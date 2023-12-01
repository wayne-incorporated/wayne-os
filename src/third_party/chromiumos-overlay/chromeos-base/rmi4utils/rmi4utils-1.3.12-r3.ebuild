# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit toolchain-funcs

DESCRIPTION="Synaptics RMI4 Utilities for Firmware Update"
HOMEPAGE="https://github.com/aduggan/rmi4utils"
SRC_URI="https://github.com/aduggan/rmi4utils/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export AR CXX RANLIB
	export STATIC_BUILD=n
}

src_install() {
	dolib.so rmidevice/librmidevice.so

	dosbin rmi4update/rmi4update
	dosbin rmihidtool/rmihidtool
}
