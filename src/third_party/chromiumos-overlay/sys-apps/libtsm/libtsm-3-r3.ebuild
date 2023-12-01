# Copyright 1999-2014 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

inherit eutils

DESCRIPTION="Terminal Emulator State Machine"
HOMEPAGE="http://cgit.freedesktop.org/~dvdhrm/libtsm"
SRC_URI="http://www.freedesktop.org/software/kmscon/releases/${P}.tar.xz"

LICENSE="LGPL-2.1 MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="!!=sys-apps/kmscon-7"
RDEPEND="${DEPEND}"

src_prepare() {
        epatch "${FILESDIR}"/0001-libtsm-add-OSC-string-callback.patch
        epatch "${FILESDIR}"/0002-libtsm-do-not-reset-scrollback-position-and-age-if-i.patch
}

src_configure() {
	econf --enable-debug=no
}
