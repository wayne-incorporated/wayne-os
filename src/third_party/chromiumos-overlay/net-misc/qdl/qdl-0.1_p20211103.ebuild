# Copyright 1999-2021 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cros-sanitizers eutils toolchain-funcs

DESCRIPTION="QDL flash loader for USB devices"
HOMEPAGE="https://github.com/andersson/qdl"
GIT_SHA1="2021b303a81ca1bcf21b7f1f23674b5c8747646f"
SRC_URI="https://github.com/andersson/qdl/archive/${GIT_SHA1}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="asan"

RDEPEND="dev-libs/libxml2:=
	virtual/libudev:="

DEPEND="${RDEPEND}"

S="${WORKDIR}/${PN}-${GIT_SHA1}"

src_prepare()
{
	eapply "${FILESDIR}"/${PN}-0.1_p20211103-last_sector.patch
	eapply_user
}

src_configure() {
	sanitizers-setup-env

	sed -i \
		-e '/^prefix/s:=.*:=/usr:' \
		-e "/^LDFLAGS/s:.*:LDFLAGS+=$($(tc-getPKG_CONFIG) libxml-2.0 libudev --libs):" \
		-e "/^CFLAGS/s:.*:CPPFLAGS+=$($(tc-getPKG_CONFIG) libxml-2.0 --cflags-only-I):" \
		Makefile || die
}
