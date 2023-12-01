# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Library to access the Linux tracing tracefs file system"
HOMEPAGE="https://www.trace-cmd.org"
SRC_URI="https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git/snapshot/${P}.tar.gz"

LICENSE="LGPL-2.1"
MAJOR_VERSION=$(ver_cut 1)
SLOT="0/${MAJOR_VERSION}"
KEYWORDS="*"
IUSE="test"

# Many files provided by this package used to be part of trace-cmd prior to version 3.0.0
RDEPEND="!<dev-util/trace-cmd-3.0.0
	dev-libs/libtraceevent:=
"
DEPEND="${RDEPEND}
	test? ( dev-util/cunit )
"

PATCHES=(
	"${FILESDIR}/0001-libtracefs-Make-sure-32-bit-works-on-64-bit-file-sys.patch"
)

src_configure() {
	export pkgconfig_dir=/usr/$(get_libdir)/pkgconfig
	export prefix=/usr
}
