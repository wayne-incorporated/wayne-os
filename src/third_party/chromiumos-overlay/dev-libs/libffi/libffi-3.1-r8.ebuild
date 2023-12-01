# Copyright 1999-2014 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/dev-libs/libffi/libffi-3.1-r3.ebuild,v 1.2 2014/08/10 20:35:34 slyfox Exp $

EAPI=5
inherit eutils libtool multilib multilib-minimal toolchain-funcs flag-o-matic

DESCRIPTION="a portable, high level programming interface to various calling conventions"
HOMEPAGE="http://sourceware.org/libffi/"
SRC_URI="ftp://sourceware.org/pub/${PN}/${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE="debug pax_kernel static-libs test"

RDEPEND="abi_x86_32? ( !<=app-emulation/emul-linux-x86-baselibs-20130224-r1
		!app-emulation/emul-linux-x86-baselibs[-abi_x86_32(-)] )"
DEPEND="test? ( dev-util/dejagnu )"

DOCS="ChangeLog* README"

ECONF_SOURCE=${S}

pkg_setup() {
	# Check for orphaned libffi, see http://bugs.gentoo.org/354903 for example
	if [[ ${ROOT} == "/" && ${EPREFIX} == "" ]] && ! has_version ${CATEGORY}/${PN}; then
		local base="${T}"/conftest
		echo 'int main() { }' > "${base}".c
		$(tc-getCC) -o "${base}" "${base}".c -lffi >&/dev/null
		if [ $? -eq 0 ]; then
			eerror "The linker reported linking against -lffi to be working while it shouldn't have."
			eerror "This is wrong and you should find and delete the old copy of libffi before continuing."
			die "The system is in inconsistent state with unknown libffi installed."
		fi
	fi
}

src_prepare() {
	epatch \
		"${FILESDIR}"/${P}-execstack.patch \
		"${FILESDIR}"/${P}-typing_error.patch \
		"${FILESDIR}"/${PN}-clang-asm-syntax.patch \
		"${FILESDIR}"/${PN}-allow-PROT_EXEC-PROT_WRITE.patch

	sed -i -e 's:@toolexeclibdir@:$(libdir):g' Makefile.in || die #462814
	# http://sourceware.org/ml/libffi-discuss/2014/msg00060.html
	sed -i -e 's:@toolexeclibdir@:${libdir}:' libffi.pc.in || die #511726

	epatch_user
	elibtoolize
}

multilib_src_configure() {
	use userland_BSD && export HOST="${CHOST}"
	econf \
		$(use_enable static-libs static) \
		$(use_enable pax_kernel pax_emutramp) \
		$(use_enable debug)
}

multilib_src_install_all() {
	prune_libtool_files
	einstalldocs
}
