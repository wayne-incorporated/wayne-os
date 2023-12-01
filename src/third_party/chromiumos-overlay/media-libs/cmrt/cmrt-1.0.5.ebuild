# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit autotools eutils

DESCRIPTION="C for Media Runtime"
HOMEPAGE="https://github.com/01org/cmrt"
SRC_URI="https://github.com/01org/cmrt/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="-* amd64 x86"

RDEPEND="x11-libs/libdrm"

DEPEND="${RDEPEND}
	x11-libs/libva
	virtual/pkgconfig"

src_prepare() {
	epatch "${FILESDIR}/${P}-use-right-cpp.patch"
	eautoreconf
}

src_configure() {
	cros_optimize_package_for_speed
	default
}

src_install() {
	default
	prune_libtool_files
}
