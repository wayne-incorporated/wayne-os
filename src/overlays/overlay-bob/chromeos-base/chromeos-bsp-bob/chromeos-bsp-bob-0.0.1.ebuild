# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
EAPI=7

inherit appid cros-audio-configs

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-gru
"
DEPEND="${RDEPEND}"

src_install() {
	doappid "{564AC308-CBD5-485D-9EF5-EB97DBB5F264}" "CHROMEBOOK"

	# Install audio config files
	local audio_config_dir="${FILESDIR}/audio-config"
	install_audio_configs bob "${audio_config_dir}"

	# Install platform specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/*
}
