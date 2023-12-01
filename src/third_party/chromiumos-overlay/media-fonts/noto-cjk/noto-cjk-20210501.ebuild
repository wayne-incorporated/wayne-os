# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit font

DESCRIPTION="Noto Pan CJK fonts developed by Adobe"
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.bz2"

LICENSE="OFL-1.1"
SLOT="0"
KEYWORDS="*"
IUSE=""

FONT_SUFFIX="ttc"
FONT_S="${S}"
FONTDIR="/usr/share/fonts/notocjk"

# Only installs fonts
RESTRICT="strip binchecks"

src_install() {
	# call src_install() in font.eclass.
	font_src_install
}
