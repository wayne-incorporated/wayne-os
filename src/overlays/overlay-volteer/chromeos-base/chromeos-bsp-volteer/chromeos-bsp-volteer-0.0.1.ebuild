# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit appid cros-unibuild udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
S="${WORKDIR}"
IUSE="volteer-borealis volteer-kernelnext volteer-manatee zephyr_ec"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/chromeos-bsp-baseboard-volteer
	chromeos-base/sof-binary
	chromeos-base/sof-topology
	!<chromeos-base/chromeos-bsp-volteer-private-0.0.2
	chromeos-base/touch_updater
	media-sound/sound_card_init
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use zephyr_ec; then
		doappid "{19D32B09-8ECB-4020-AAB1-BA88AB8CE028}" "CHROMEBOOK"
	elif use volteer-borealis; then
		doappid "{04EDAC5E-72DF-11EB-A3DD-6F5131EE15CD}" "CHROMEBOOK"
	elif use volteer-kernelnext; then
		doappid "{716105F8-A2C3-11EA-A044-33E3EAAD1A23}" "CHROMEBOOK"
	elif use volteer-manatee; then
		doappid "{D5C68FC4-8B32-11EB-B809-CF1CBAA251C8}" "CHROMEBOOK"
	else
		doappid "{77BE25D7-AFB8-4E3C-A7D2-1FACE1B186E3}" "CHROMEBOOK"
	fi

	unibuild_install_files audio-files

	udev_dorules "${FILESDIR}"/udev/*.rules
}
