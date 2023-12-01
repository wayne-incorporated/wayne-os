# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit dlc

DESCRIPTION="TTS es-us Language Pack for Chromium OS"
HOMEPAGE="https://www.chromium.org/chromium-os"
SRC_URI="gs://chromeos-localmirror/distfiles/languagepack-tts-es-us-${PV}.tar.xz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

IUSE="dlc"
REQUIRED_USE="dlc"

# ALlocate 1.5x the 4 KiB blocks needed for the initial version.
DLC_PREALLOC_BLOCKS="2425"

# Enable scaled design.
DLC_SCALED=true

# Override S, as we store everything in the root directory of the archive.
S="${WORKDIR}"

src_install() {
	# Setup DLC paths.
	insinto "$(dlc_add_path /)"

	doins voice.zvoice

	dlc_src_install
}
