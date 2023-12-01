# Copyright 1999-2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

# Install old SONAME library for old prebuilt binaries.

EAPI=7

inherit eutils multilib toolchain-funcs flag-o-matic multilib-minimal

# Official patches
# See ftp://ftp.cwru.edu/pub/bash/readline-6.3-patches/
PLEVEL=${PV##*_p}
MY_PV=${PV/_p*}
MY_PV=${MY_PV/_/-}
MY_P=${PN}-${MY_PV}
[[ ${PV} != *_p* ]] && PLEVEL=0
patches() {
	[[ ${PLEVEL} -eq 0 ]] && return 1
	local opt=$1
	eval set -- {1..${PLEVEL}}
	set -- $(printf "${PN}${MY_PV/\.}-%03d " "$@")
	if [[ ${opt} == -s ]] ; then
		echo "${@/#/${DISTDIR}/}"
	else
		local u
		for u in ftp://ftp.cwru.edu/pub/bash mirror://gnu/${PN} ; do
			printf "${u}/${PN}-${MY_PV}-patches/%s " "$@"
		done
	fi
}

DESCRIPTION="Another cute console display library"
HOMEPAGE="https://tiswww.case.edu/php/chet/readline/rltop.html"
SRC_URI="mirror://gnu/${PN}/${MY_P}.tar.gz $(patches)"

LICENSE="GPL-3"
SLOT="6"
KEYWORDS="*"
IUSE=""

RDEPEND=">=sys-libs/ncurses-5.9-r3:0=[${MULTILIB_USEDEP}]
	!<=sys-libs/readline-8.1_p1-r1"
DEPEND="${RDEPEND}
	virtual/pkgconfig"

S=${WORKDIR}/${MY_P}

PATCHES=(
	"${FILESDIR}"/${PN}-5.0-no_rpath.patch
	"${FILESDIR}"/${PN}-6.2-rlfe-tgoto.patch #385091
	"${FILESDIR}"/${PN}-6.3-fix-long-prompt-vi-search.patch
	"${FILESDIR}"/${PN}-6.3-read-eof.patch
)

src_unpack() {
	unpack ${MY_P}.tar.gz
}

src_prepare() {
	[[ ${PLEVEL} -gt 0 ]] && eapply -p0 $(patches -s)
	default

	# Force ncurses linking. #71420
	# Use pkg-config to get the right values. #457558
	local ncurses_libs=$($(tc-getPKG_CONFIG) ncurses --libs)
	sed -i \
		-e "/^SHLIB_LIBS=/s:=.*:='${ncurses_libs}':" \
		support/shobj-conf || die
	sed -i \
		-e "/^[[:space:]]*LIBS=.-lncurses/s:-lncurses:${ncurses_libs}:" \
		examples/rlfe/configure || die

	# fix building under Gentoo/FreeBSD; upstream FreeBSD deprecated
	# objformat for years, so we don't want to rely on that.
	sed -i -e '/objformat/s:if .*; then:if true; then:' support/shobj-conf || die

	ln -s ../.. examples/rlfe/readline # for local readline headers
}

src_configure() {
	# fix implicit decls with widechar funcs
	append-cppflags -D_GNU_SOURCE
	# https://lists.gnu.org/archive/html/bug-readline/2010-07/msg00013.html
	append-cppflags -Dxrealloc=_rl_realloc -Dxmalloc=_rl_malloc -Dxfree=_rl_free

	# Make sure configure picks a better ar than `ar`. #484866
	export ac_cv_prog_AR=$(tc-getAR)

	# Force the test since we used sed above to force it.
	export bash_cv_termcap_lib=ncurses

	# Control cross-compiling cases when we know the right answer.
	# In cases where the C library doesn't support wide characters, readline
	# itself won't work correctly, so forcing the answer below should be OK.
	if tc-is-cross-compiler ; then
		export bash_cv_func_sigsetjmp='present'
		export bash_cv_func_ctype_nonascii='yes'
		export bash_cv_wcwidth_broken='no' #503312
	fi

	# This is for rlfe, but we need to make sure LDFLAGS doesn't change
	# so we can re-use the config cache file between the two.
	append-ldflags -L.

	multilib-minimal_src_configure
}

multilib_src_configure() {
	ECONF_SOURCE=${S} \
	econf \
		--cache-file="${BUILD_DIR}"/config.cache \
		--docdir='$(datarootdir)'/doc/${PF} \
		--with-curses \
		--disable-static
}

multilib_src_install() {
	dolib.so shlib/libreadline.so.6.3
	dosym  libreadline.so.6.3 "/usr/$(get_libdir)/libreadline.so.6"
}
