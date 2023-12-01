# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
EAPI=5

inherit appid cros-audio-configs udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="scarlet-arcnext scarlet-kernelnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-gru
"
DEPEND="${RDEPEND}"

src_install() {
	if use scarlet-arcnext; then
		doappid "{8A1450CE-E1AF-DF7B-D242-74AB10A7B1F9}" "CHROMEBOOK"
	elif use scarlet-kernelnext; then
		doappid "{43491D40-6EDC-402B-A4FE-0D270B3F0CD6}" "CHROMEBOOK"
	else
		doappid "{F1C30EB2-8429-4A18-9321-93E224753A98}" "CHROMEBOOK"
	fi

	# Install audio config files
	local audio_config_dir="${FILESDIR}/audio-config"
	install_audio_configs scarlet "${audio_config_dir}"

	# Install platform specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/*

	# Scarlet uses multiple vendors for the same wacom touchscreen device,
	# thus it needs a way to differentiate between those.
	exeinto "/opt/google/touch/scripts"
	doexe "${FILESDIR}"/get_board_specific_wacom_hwid.sh

	# Install udev rules.
	udev_dorules "${FILESDIR}"/udev-rules/*.rules
}
