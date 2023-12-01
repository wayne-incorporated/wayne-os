# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit cros-audio-configs
inherit appid
inherit udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="eve-arcnext eve-arc-r eve-arm64 eve-campfire eve-kvm eve-lacros eve-swap eve-userdebug eve-kernelnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/genius-app-data-eve
"

DEPEND="${RDEPEND}"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use eve-userdebug; then
		doappid "{20C53672-DEE7-4824-A131-D9547AB409ED}" "CHROMEBOOK"
	elif use eve-kernelnext; then
		doappid "{A114D05C-9537-11EA-B8FB-DF3BBDF917E8}" "CHROMEBOOK"
	elif use eve-kvm; then
		doappid "{75563B98-6669-53BA-9A12-D48141DA0C14}" "CHROMEBOOK"
	elif use eve-arcnext; then
		doappid "{12E4F4E4-4482-2F56-F445-7EDA56433A9A}" "CHROMEBOOK"
	elif use eve-arc-r; then
		doappid "{A0CD5EC9-768D-4987-A061-88B0A6ABD9C3}" "CHROMEBOOK"
	elif use eve-arm64; then
		doappid "{AD912019-11B6-4239-8937-AF902C074065}" "CHROMEBOOK"
	elif use eve-campfire; then
		doappid "{BF8505B6-AF41-4F34-8F6D-1768FEF18753}" "CHROMEBOOK"
	elif use eve-swap; then
		doappid "{10DF45F1-19D4-4045-B254-10B37180262A}" "CHROMEBOOK"
	elif use eve-lacros; then
		doappid "{4804541E-21B7-4857-951C-84668BF10104}" "CHROMEBOOK"
	else
		doappid "{01906EA2-3EB2-41F1-8F62-F0B7120EFD2E}" "CHROMEBOOK"
	fi

	# Install platform specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/*

	# Install audio config files
	install_audio_configs eve "${FILESDIR}/audio-config"

	# Install platform-specific internal keyboard keymap.
	# It should probbaly go into /lib/udev/hwdb.d but
	# unfortunately udevadm on 64 bit boxes does not check
	# that directory (it wants to look in /lib64/udev).
	insinto "${EPREFIX}/etc/udev/hwdb.d"
	doins "${FILESDIR}/61-eve-keyboard.hwdb"

	# Intall a rule tagging keyboard as having updated layout
	udev_dorules "${FILESDIR}/61-eve-keyboard.rules"

	# Install platform-specific bluetooth sysprops
	insinto "/etc/bluetooth/sysprops.conf.d"
	insopts -m0640
	doins "${FILESDIR}/eve-bluetooth-sysprops.conf"
	insopts -m0644

	# Install device-specific automatic brightness model parameters.
	insinto "/usr/share/chromeos-assets/autobrightness"
	doins "${FILESDIR}/autobrightness/model_params.json"
}
