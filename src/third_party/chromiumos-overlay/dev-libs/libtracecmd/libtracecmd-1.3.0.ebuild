# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Library allowing access to trace-cmd features"
HOMEPAGE="https://www.trace-cmd.org"
SRC_URI="https://git.kernel.org/pub/scm/utils/trace-cmd/trace-cmd.git/snapshot/trace-cmd-${P}.tar.gz"

LICENSE="LGPL-2.1"
MAJOR_VERSION=$(ver_cut 1)
SLOT="0/${MAJOR_VERSION}"
KEYWORDS="*"
IUSE="test"
S="${WORKDIR}/trace-cmd-${P}"

RDEPEND="
	dev-libs/libtraceevent:=
	dev-libs/libtracefs:=
"
DEPEND="${RDEPEND}
	sys-kernel/linux-headers
	test? ( dev-util/cunit )
"

PATCHES=(
	"${FILESDIR}/0001-trace-cmd-Make-sure-32-bit-works-on-64-bit-file-syst.patch"
)

src_configure() {
	export pkgconfig_dir=/usr/$(get_libdir)/pkgconfig
	export prefix=/usr
}

src_compile() {
	emake NO_PYTHON=1 libs
}

src_install() {
	emake NO_PYTHON=1 DESTDIR="${D}" install_libs
}
