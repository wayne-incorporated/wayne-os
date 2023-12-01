# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid cros-audio-configs

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-kunimitsu
"
DEPEND="${RDEPEND}"

src_install() {
	doappid "{E020B8D4-CA96-4599-84DA-5017455418AE}" "CHROMEBOOK"

	# Install platform specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/*

	# Install audio config files
	install_audio_configs sentry "${FILESDIR}/audio-config"

	# Install device-specific custom dptf profile.
	insinto "/etc/dptf"
	doins "${FILESDIR}"/dptf/*
}
