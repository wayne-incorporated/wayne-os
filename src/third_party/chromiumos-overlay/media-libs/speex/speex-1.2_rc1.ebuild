# Copyright 1999-2009 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/media-libs/speex/speex-1.2_rc1.ebuild,v 1.8 2009/12/11 19:59:55 ranger Exp $

EAPI=5

inherit autotools eutils flag-o-matic

MY_P=${P/_} ; MY_P=${MY_P/_p/.}

DESCRIPTION="Audio compression format designed for speech."
HOMEPAGE="http://www.speex.org"
SRC_URI="http://downloads.xiph.org/releases/speex/${MY_P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="ogg sse neon"

RDEPEND="ogg? ( media-libs/libogg )"
DEPEND="${RDEPEND}"

S=${WORKDIR}/${MY_P}

src_unpack() {
	unpack ${A}
	cd "${S}"
	epatch "${FILESDIR}"/${P}-configure.patch
	epatch "${FILESDIR}"/${P}-backup-input-length.patch
	epatch "${FILESDIR}"/${P}-fix-sse-inner-product.patch
	epatch "${FILESDIR}"/${P}-add-neon-optimization.patch

	sed -i -e 's:noinst_PROGRAMS:check_PROGRAMS:' \
		"${S}"/libspeex/Makefile.am \
		|| die "unable to disable tests building"
	eautoreconf
}

src_compile() {
	cros_optimize_package_for_speed
	append-flags -D_FILE_OFFSET_BITS=64 -DRESAMPLE_FORCE_FULL_SINC_TABLE

	econf $(use_enable sse) $(use_enable neon) $(use_enable ogg)
	emake || die "emake failed."
}

src_install() {
	emake DESTDIR="${D}" docdir="/usr/share/doc/${PF}" \
		install || die "emake install failed."

	dodoc AUTHORS ChangeLog NEWS README* TODO
}
