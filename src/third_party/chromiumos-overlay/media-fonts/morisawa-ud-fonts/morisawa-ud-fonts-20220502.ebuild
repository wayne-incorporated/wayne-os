# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# $Header: $
EAPI="7"

inherit font

DESCRIPTION="BIZ UD Fonts by Morisawa"
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="OFL-1.1"
SLOT="0"
KEYWORDS="*"
IUSE=""

FONT_SUFFIX="ttf"
FONT_S="${S}"
FONTDIR="/usr/share/fonts/morisawa"


# Only installs fonts
RESTRICT="strip binchecks"

src_install() {
	# call src_install() in font.eclass.
	font_src_install
}
