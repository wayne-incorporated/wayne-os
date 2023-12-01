# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid cros-audio-configs

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0" # TODO (b/180408941): convert this to cros-workon
KEYWORDS="-* amd64 x86"
IUSE="lars-kernelnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-kunimitsu
"
DEPEND="${RDEPEND}"

src_install() {
	if use lars-kernelnext; then
		doappid "{971C0768-7070-11EB-B322-171AAF8A95A8}" "CHROMEBOOK"
	else
		doappid "{E7507B05-EC5C-437C-9878-E870E20111BC}" "CHROMEBOOK"
	fi

	# Install audio config files
	install_audio_configs lars "${FILESDIR}/audio-config"
}
