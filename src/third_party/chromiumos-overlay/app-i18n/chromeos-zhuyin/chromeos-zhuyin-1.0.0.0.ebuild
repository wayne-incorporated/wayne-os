# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"
inherit eutils

DESCRIPTION="The Chinese Zhuyin input engine for IME extension API"
HOMEPAGE="https://code.google.com/p/google-input-tools/"
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}/${PN}"

src_prepare() {
	epatch "${FILESDIR}"/${P}-insert-public-key.patch
	epatch "${FILESDIR}"/${P}-fix-permission.patch
}

src_install() {
	insinto /usr/share/chromeos-assets/input_methods/zhuyin
	doins -r *
}
