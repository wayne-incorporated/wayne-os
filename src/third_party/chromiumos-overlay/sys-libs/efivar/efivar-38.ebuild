# Copyright 2014-2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit toolchain-funcs

DESCRIPTION="Tools and library to manipulate EFI variables"
HOMEPAGE="https://github.com/rhinstaller/efivar"
SRC_URI="https://github.com/rhinstaller/efivar/releases/download/${PV}/${P}.tar.bz2"

LICENSE="GPL-2"
SLOT="0/1"
KEYWORDS="*"
IUSE="doc test"
RESTRICT="!test? ( test )"

BDEPEND="
	doc? ( app-text/mandoc )
	test? ( sys-boot/grub:2 )
"
RDEPEND="
	dev-libs/popt
"
DEPEND="${RDEPEND}
	>=sys-kernel/linux-headers-3.18
	virtual/pkgconfig
"

src_prepare() {
	local PATCHES=(
		"${FILESDIR}"/efivar-38-march-native.patch
		"${FILESDIR}"/efivar-38-Makefile-dep.patch
		"${FILESDIR}"/efivar-38-binutils-2.36.patch
		"${FILESDIR}"/efivar-38-ld-locale.patch
		"${FILESDIR}"/efivar-38-glibc-2.36.patch
		"${FILESDIR}"/efivar-38-lld-fixes.patch
		"${FILESDIR}"/efivar-38-efisecdb-musl.patch
		"${FILESDIR}"/efivar-38-efisecdb-optarg.patch

		# Rejected upstream, keep this for ia64 support
		"${FILESDIR}"/efivar-38-ia64-relro.patch

		# Fix hardcoded pkg-config:
		# https://github.com/rhboot/efivar/pull/236
		"${FILESDIR}"/efivar-38-pkgconfig-fix.patch
		# Allow disabling docs so we don't need mandoc
		# https://github.com/rhboot/efivar/pull/241
		"${FILESDIR}"/efivar-38-disable-docs.patch
	)
	default
}

src_configure() {
	unset CROSS_COMPILE
	export COMPILER=$(tc-getCC)
	export HOSTCC=$(tc-getBUILD_CC)

	tc-ld-disable-gold

	export libdir="/usr/$(get_libdir)"

	# https://bugs.gentoo.org/562004
	unset LIBS

	# Avoid -Werror
	export ERRORS=

	if ! use doc; then
		# Skip building the man pages.
		export ENABLE_DOCS=0
	fi

	if [[ -n ${GCC_SPECS} ]]; then
		# The environment overrides the command line.
		GCC_SPECS+=":${S}/src/include/gcc.specs"
	fi

	# Used by tests/Makefile
	export GRUB_PREFIX=grub
}
