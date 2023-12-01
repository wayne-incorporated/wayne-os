# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Logitech PTZ Pro 2 firmware"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="BSD-Logitech"
SLOT="0"
KEYWORDS="*"

RDEPEND="sys-apps/logitech-updater"
DEPEND=""

S="${WORKDIR}"

src_install() {
	insinto /lib/firmware/logitech/ptzpro2
	doins "ptzpro2_video.bin"
	doins "ptzpro2_eeprom.s19"
	doins "ptzpro2_mcu2.bin"
	doins "ptzpro2_video.bin.sig"
	doins "ptzpro2_eeprom.s19.sig"
	doins "ptzpro2_mcu2.bin.sig"
}
