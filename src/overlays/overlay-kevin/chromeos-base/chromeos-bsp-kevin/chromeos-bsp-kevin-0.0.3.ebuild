# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid cros-audio-configs udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="kevin-arcnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	>=chromeos-base/chromeos-bsp-baseboard-gru-0.0.3
	chromeos-base/chromeos-touch-config-kevin
"
DEPEND="${RDEPEND}"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use kevin-arcnext; then
		doappid "{35EF2A87-CD2B-62EE-E83C-F6E0F71C7FEE}" "CHROMEBOOK"
	else
		doappid "{92A7272A-834A-47A3-9112-E8FD55831660}" "CHROMEBOOK" # kevin
	fi

	# Install audio config files
	local audio_config_dir="${FILESDIR}/audio-config"
	install_audio_configs kevin "${audio_config_dir}"

	# Disable touchpad wakeup source completely
	udev_dorules "${FILESDIR}/93-powerd-overrides.rules"
}
