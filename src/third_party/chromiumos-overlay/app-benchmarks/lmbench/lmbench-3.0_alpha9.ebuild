# Copyright 1999-2009 Gentoo Foundation
# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
inherit eutils toolchain-funcs multilib

MY_P=${P/_alpha/-a}
DESCRIPTION="Suite of simple, portable benchmarks"
HOMEPAGE="http://www.bitmover.com/lmbench/whatis_lmbench.html"
SRC_URI="mirror://sourceforge/${PN}/development/${MY_P}/${MY_P}.tgz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	net-libs/libtirpc
"
DEPEND="
	${RDEPEND}
	virtual/pkgconfig
	"

S="${WORKDIR}/${MY_P}"

PATCHES=(
	"${FILESDIR}/lmbench-cflags.patch"
)

src_prepare() {
	# shellcheck disable=SC2016
	sed -i \
		-e "/\$(BASE)\/lib/s:/lib:/$(get_libdir):g" \
		-e '/-ranlib/s:ranlib:$(RANLIB):' \
		src/Makefile || die
	default
}

src_configure() {
	append-lfs-flags
	default
}

_emake() {
	# NB: include "-O1" in CFLAGS because:
	# (a) we want to respect most CFLAGS from the host build system (e.g.,
	#     cross-compilation, etc.); but
	# (b) lmbench intentionally overrides CFLAGS with its preferred
	#     optimization levels.
	# As a middle ground, we force our CFLAGS back in, but copy over the
	# optimization level from lmbench's Makefile.
	emake \
		AR="$(tc-getAR)" \
		RANLIB="$(tc-getRANLIB)" \
		CC="$(tc-getCC)" \
		CPPFLAGS="${CPPFLAGS}" \
		EXTRA_CFLAGS="${CFLAGS} -O1 $($(tc-getPKG_CONFIG) libtirpc --cflags)" \
		LDLIBS="$($(tc-getPKG_CONFIG) libtirpc --libs)" \
		"$@"
}

src_compile() {
	_emake build
}

src_install() {
	cd src || die
	_emake BASE="${ED}"/usr install

	dodir /usr/share
	mv "${ED}"/usr/man "${ED}"/usr/share || die

	cd "${S}" || die
	mv "${ED}"/usr/bin/stream{,.lmbench}  || die

	# avoid file collision with sys-apps/util-linux
	mv "${ED}"/usr/bin/line{,.lmbench} || die
}
