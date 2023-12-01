# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid cros-audio-configs

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE=""
S="${WORKDIR}"

RDEPEND="chromeos-base/chromeos-bsp-baseboard-gru"
DEPEND="${RDEPEND}"

src_install() {
	doappid "{8FF51C76-7EB0-46A1-9B00-1E2975761BB7}" "CHROMEBOOK" # rainier

	# Install audio config files
	local audio_config_dir="${FILESDIR}/audio-config"
	install_audio_configs rainier "${audio_config_dir}"


}
