# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit font

MY_P="IPAexfont${PV/.}"

DESCRIPTION="Japanese IPA extended TrueType fonts"
HOMEPAGE="https://moji.or.jp/ipafont/"
SRC_URI="https://moji.or.jp/wp-content/ipafont/IPAexfont/${MY_P}.zip"

LICENSE="IPAfont"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

BDEPEND="app-arch/unzip"
S="${WORKDIR}/${MY_P}"

FONT_SUFFIX="ttf"
FONTDIR="/usr/share/fonts/ipa-jp"

src_prepare() {
	default
	# Remove IPAexGothic since it's too big.
	rm "${S}/ipaexg.ttf" || die
}

src_install() {
	font_src_install
}
