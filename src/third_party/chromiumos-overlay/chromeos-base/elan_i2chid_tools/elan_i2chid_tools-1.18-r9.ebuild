# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

inherit toolchain-funcs

DESCRIPTION="Elan Touchscreen I2C-HID Tools for Firmware Update"
HOMEPAGE="https://github.com/PaulLiang01043/elan_i2chid_tools"
SRC_URI="http://storage.googleapis.com/chromeos-localmirror/distfiles/elan_i2chid_tools-${PV}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC
}

src_install() {
	newsbin i2chid_read_fwid/bin/i2chid_read_fwid elan_i2chid_read_fwid
	newsbin i2chid_iap_v2/bin/i2chid_iap_v2 elan_i2chid_iap

	insinto /usr/share/${PN}
	doins "${FILESDIR}"/fwid_mapping_table.txt
}
