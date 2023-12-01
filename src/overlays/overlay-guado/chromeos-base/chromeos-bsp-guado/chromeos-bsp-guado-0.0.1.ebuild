# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid cros-audio-configs

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="guado-cfm"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-jecht
	media-libs/go2001-fw
	media-libs/go2001-rules
	!<media-sound/adhd-0.0.1-r1687
"
DEPEND="${RDEPEND}"

src_install() {
	if use guado-cfm; then
		doappid "{5A5EE14C-32AC-D8D9-ACEA-C6A74DE79B63}" "CHROMEBOX"
	else
		doappid "{8AA6D9AC-6EBC-4288-A615-171F56F66B4E}" "CHROMEBOX"
	fi

	# Install ucm-config files
	local audio_config_dir="${FILESDIR}/audio-config"
	install_audio_configs guado "${audio_config_dir}"
}
