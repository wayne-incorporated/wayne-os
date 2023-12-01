# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit font

DESCRIPTION="Nanum Gothic fonts released by Naver Inc. under OFL"
HOMEPAGE="http://hangeul.naver.com/index.nhn"

# download link does not have a version number.
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.bz2"

LICENSE="OFL-1.1"
SLOT="0"
KEYWORDS="*"
IUSE=""

FONT_SUFFIX="ttf"
FONT_S="${S}"
FONTDIR="/usr/share/fonts/ko-nanum"

# Only installs fonts
RESTRICT="strip binchecks"

src_install() {
	# call src_install() in font.eclass.
	font_src_install
}
