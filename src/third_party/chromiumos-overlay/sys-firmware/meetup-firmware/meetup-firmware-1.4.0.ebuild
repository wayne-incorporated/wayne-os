# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Logitech MeetUp firmware"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="BSD-Logitech"
SLOT="0"
KEYWORDS="*"

RDEPEND="sys-apps/logitech-updater"
DEPEND=""

S="${WORKDIR}"

src_install() {
	insinto /lib/firmware/logitech/meetup
	doins "meetup_video.bin"
	doins "meetup_eeprom.s19"
	doins "meetup_codec.bin"
	doins "meetup_audio.bin"
	doins "meetup_ble.bin"
	doins "meetup_eeprom_logicool.s19"
	doins "meetup_audio_logicool.bin"
	doins "meetup_video.bin.sig"
	doins "meetup_eeprom.s19.sig"
	doins "meetup_codec.bin.sig"
	doins "meetup_audio.bin.sig"
	doins "meetup_ble.bin.sig"
	doins "meetup_eeprom_logicool.s19.sig"
	doins "meetup_audio_logicool.bin.sig"
}
