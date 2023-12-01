# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid cros-unibuild cros-audio-configs

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="fizz-cfm fizz-kernelnext kernel-4_4"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="chromeos-base/chromeos-bsp-baseboard-fizz"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use fizz-cfm; then
		doappid "{83703798-86A9-3073-D590-0D0937639CB0}" "CHROMEBOX"
	elif use fizz-kernelnext; then
		doappid "{4E92DCBB-A7F8-4AC1-85A2-B63D0FBBFD1B}" "CHROMEBOX"
	else
		doappid "{0C1E39B7-DAE6-4972-8004-E96F60D9342C}" "CHROMEBOX"
	fi

	# Install audio config files
	local audio_config_dir="${FILESDIR}/audio-config"
	if use kernel-4_4; then
		audio_config_dir="${FILESDIR}/audio-config-4_4"
	fi
	install_audio_configs fizz "${audio_config_dir}"

	# Install board-specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd/*

	# Install board-specific dptf.
	unibuild_install_files thermal-files
}
