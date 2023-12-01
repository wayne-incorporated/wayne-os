# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit autotools eutils

DESCRIPTION="A test program for capturing input device events."
HOMEPAGE="https://gitlab.freedesktop.org/libevdev/evtest/"
SRC_URI="https://gitlab.freedesktop.org/libevdev/evtest/-/archive/${P}/evtest-${P}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE="+xml"

BDEPEND="
	virtual/pkgconfig
	app-text/docbook-xml-dtd:4.5
"

S=${WORKDIR}/${PN}-${P}

PATCHES=(
	"${FILESDIR}/1.35-add-safe-flag.patch"
)

src_prepare() {
	default
	eautoreconf
}
