# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Command-line flags module for Unix shell scripts"
HOMEPAGE="https://github.com/kward/shflags"
SRC_URI="https://github.com/kward/shflags/archive/v${PV}.tar.gz -> ${P}.tgz"

LICENSE="LGPL-2.1"
SLOT="0"
KEYWORDS="*"
IUSE="examples"

PATCHES=(
	"${FILESDIR}/0001-Remove-export-of-FLAGS_ARGC.patch"
	"${FILESDIR}/0002-Removed-FLAGS_ARGC-harder.patch"
	"${FILESDIR}/0003-Removed-FLAGS_ARGC-harder.patch"
)

src_test() {
	sh test_runner || die
}

src_install() {
	dodoc README* doc/*.txt
	insinto /usr/share/misc
	doins "${PN}"
	use examples && dodoc examples/*
}
