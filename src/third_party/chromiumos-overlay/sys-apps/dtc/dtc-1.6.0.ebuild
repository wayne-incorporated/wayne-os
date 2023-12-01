# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

PYTHON_COMPAT=( python3_{6..9} )
DISTUTILS_OPTIONAL="1"
inherit multilib toolchain-funcs eutils distutils-r1

if [[ ${PV} == "9999" ]] ; then
	EGIT_REPO_URI="git://git.kernel.org/pub/scm/utils/dtc/dtc.git"
	inherit git-r3
else
	SRC_URI="mirror://kernel/software/utils/${PN}/${P}.tar.xz"
	KEYWORDS="*"
fi

DESCRIPTION="Open Firmware device tree compiler"
HOMEPAGE="https://devicetree.org/ https://git.kernel.org/cgit/utils/dtc/dtc.git/"

LICENSE="GPL-2"
SLOT="0"
IUSE="python static-libs"

RDEPEND="python? ( ${PYTHON_DEPS} )"
DEPEND="${RDEPEND}
	python? (
		dev-lang/swig
	)
	sys-devel/bison
	sys-devel/flex
"
REQUIRED_USE="python? ( ${PYTHON_REQUIRED_USE} )"
DOCS="
	${S}/Documentation/dt-object-internal.txt
	${S}/Documentation/dts-format.txt
	${S}/Documentation/manual.txt
"

src_prepare() {
	eapply "${FILESDIR}"/*.patch

	default

	sed -i \
		-e '/^CFLAGS =/s:=:+=:' \
		-e '/^CPPFLAGS =/s:=:+=:' \
		-e 's:-Werror::' \
		-e 's:-g -Os::' \
		-e "/^PREFIX =/s:=.*:= ${EPREFIX}/usr:" \
		-e "/^LIBDIR =/s:=.*:= \$(PREFIX)/$(get_libdir):" \
		Makefile || die

	if use python ; then
		cd pylibfdt || die
		distutils-r1_src_prepare
	fi
}

src_configure() {
	tc-export AR CC PKG_CONFIG
	export V=1

	if use python ; then
		cd pylibfdt || die
		distutils-r1_src_configure
	fi
}

src_compile() {
	emake NO_PYTHON=1

	if use python ; then
		cd pylibfdt || die
		distutils-r1_src_compile
	fi
}

src_install() {
	NO_PYTHON=1 default

	use static-libs || find "${ED}" -name '*.a' -delete

	if use python ; then
		cd pylibfdt || die
		distutils-r1_src_install
	fi
}
