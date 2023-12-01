# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit toolchain-funcs flag-o-matic

DESCRIPTION="DOS filesystem tools - provides mkdosfs, mkfs.msdos, mkfs.vfat"
HOMEPAGE="https://github.com/dosfstools/dosfstools"
SRC_URI="https://github.com/dosfstools/dosfstools/releases/download/v${PV}/${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="*"
IUSE="compat +iconv test"
RESTRICT="!test? ( test )"

BDEPEND="
	test? ( app-editors/vim-core )
	iconv? ( virtual/libiconv )
"

PATCHES="${FILESDIR}/${PN}-4.2-use-open-fd.patch"

src_configure() {
	local myeconfargs=(
		$(use_enable compat compat-symlinks)
		$(use_with iconv)
	)
	econf "${myeconfargs[@]}"
}

src_install() {
	default
	if ! use compat ; then
		# Keep fsck -t vfat and mkfs -t vfat working, bug 584980.
		dosym fsck.fat /usr/sbin/fsck.vfat
		dosym mkfs.fat /usr/sbin/mkfs.vfat
	fi
}
