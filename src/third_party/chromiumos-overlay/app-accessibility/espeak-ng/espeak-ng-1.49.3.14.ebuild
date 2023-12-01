# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v3
#
# Local fork with Chrome-specific port:
# https://chromium.googlesource.com/chromiumos/third_party/espeak-ng
# See README.chrome in the "chrome" branch for details.

EAPI=6

DESCRIPTION="Text-to-speech engine"
HOMEPAGE="https://github.com/espeak-ng/espeak-ng"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

src_install() {
	insinto /usr/share/chromeos-assets/speech_synthesis/espeak-ng
	doins espeak-ng/chrome-extension/*.{png,js,json,css,html}

	insinto /usr/share/chromeos-assets/speech_synthesis/espeak-ng/js
	doins espeak-ng/chrome-extension/js/*.{js,data,wasm}
}
