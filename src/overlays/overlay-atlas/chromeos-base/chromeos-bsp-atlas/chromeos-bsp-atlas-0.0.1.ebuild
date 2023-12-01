# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

inherit appid
inherit cros-audio-configs
inherit udev

DESCRIPTION="Atlas board-specific ebuild that pulls in necessary ebuilds as
dependencies or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="atlas-kvm atlas-connectivitynext atlas-kernelnext atlas-signingnext has_private_audio_topology kernel-4_4"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
DEPEND="
	chromeos-base/chromeos-bsp-baseboard-krabbylake
"

RDEPEND="${DEPEND}
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/chromeos-tcon-updater-atlas
"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use atlas-kvm; then
		doappid "{ED3D806C-3D7A-46E2-9604-13382FC1D55B}" "CHROMEBOOK"
	elif use atlas-connectivitynext; then
		doappid "{31A53FCC-241C-4439-8735-0A89AD9FB7A5}" "CHROMEBOOK"
	elif use atlas-kernelnext; then
		doappid "{DA55FC40-8B29-11EB-A477-BB6BC4E5094A}" "CHROMEBOOK"
	elif use atlas-signingnext; then
		doappid "{AA7037F3-BAEA-46BD-9F49-ADE7F801E601}" "CHROMEBOOK"
	else
		doappid "{DB5199C7-358B-4E1F-B4F6-AF6D2DD01A38}" "CHROMEBOOK"
	fi

	# Install platform specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/*

	# Install audio config files
	if ! use kernel-4_4; then
		local audio_config_dir="${FILESDIR}/kernelnext-audio-config"
	else
		local audio_config_dir="${FILESDIR}/audio-config"
	fi
	install_audio_configs atlas "${audio_config_dir}"

	local waves_dir=/usr/share/alsa/ucm/waves
	dodir "${waves_dir}"
	insinto "${waves_dir}"
	local waves_enable_config="${audio_config_dir}/waves"
	if use has_private_audio_topology; then
		doins "${waves_enable_config}/EnableSeq.conf"
	else
		newins "${waves_enable_config}/EnableSeq.conf.empty" EnableSeq.conf
	fi
	# Install platform-specific internal keyboard keymap.
	# It should probably go into /lib/udev/hwdb.d but
	# unfortunately udevadm on 64 bit boxes does not check
	# that directory (it wants to look in /lib64/udev).
	insinto "${EPREFIX}/etc/udev/hwdb.d"
	doins "${FILESDIR}/61-atlas-keyboard.hwdb"

	# Intall a rule tagging keyboard as having updated layout
	udev_dorules "${FILESDIR}/61-atlas-keyboard.rules"

	# Install /etc/init/generate_rdc_update.conf, which reads DSM calibration
	# data from VPD and writes to /run/cras/rdc_update.bin
	insinto /etc/init
	doins "${FILESDIR}"/init/generate_rdc_update.conf

	# Install device-specific automatic brightness model parameters.
	insinto "/usr/share/chromeos-assets/autobrightness"
	doins "${FILESDIR}/autobrightness/model_params.json"

	# Install device-specific custom dptf profile.
	insinto "/etc/dptf"
	doins "${FILESDIR}"/dptf/*
}
