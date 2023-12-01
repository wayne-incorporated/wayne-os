# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid cros-audio-configs

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/chromeos-bsp-baseboard-glados
"
DEPEND="${RDEPEND}"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	doappid "{B00DD0BC-D2C9-BAB4-E66C-81AE3F5A7CED}" "CHROMEBOOK"

	# Install audio configs.
	install_audio_configs cave "${FILESDIR}/audio-config"

	# Install platform specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/*
}
