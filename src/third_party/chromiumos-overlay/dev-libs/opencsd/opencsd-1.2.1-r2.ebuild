# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit toolchain-funcs

DESCRIPTION="Open source CoreSight trace decode library"
HOMEPAGE="https://github.com/Linaro/OpenCSD"
SRC_URI="https://github.com/linaro/${PN}/archive/${P}.tar.xz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="debug"

RDEPEND=""

PATCHES=( "${FILESDIR}/${PN}-1.2.1-snapshot-algorithm.patch" )

src_compile() {
	cros_enable_cxx_exceptions
	use debug && DEBUG_OPT=1

	# Opencsd build is flaky at times, use "-j1" to avoid any races.
	emake -j1 -C decoder/build/linux/ \
		LINUX64=1 DEBUG=${DEBUG_OPT} \
		MASTER_CC="$(tc-getCC)" \
		MASTER_CXX="$(tc-getCXX)" \
		MASTER_LIB="$(tc-getAR)" \
		MASTER_LINKER="$(tc-getCXX)"
}

src_install() {
	dolib.a decoder/lib/builddir/libopencsd.a decoder/lib/builddir/libopencsd_c_api.a
	doheader -r decoder/include/opencsd
}
