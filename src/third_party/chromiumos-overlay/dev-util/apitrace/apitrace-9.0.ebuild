# Copyright 1999-2018 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
inherit cmake-multilib python-single-r1

DESCRIPTION="Tool for tracing, analyzing, and debugging graphics APIs"
HOMEPAGE="https://github.com/apitrace/apitrace"
SRC_URI="https://github.com/${PN}/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="MIT"
LICENSE+=" BSD CC-BY-3.0 CC-BY-4.0 public-domain" #bundled snappy
SLOT="0"
KEYWORDS="*"
IUSE="+cli egl opengl opengles qt5 system-snappy X"
REQUIRED_USE="${PYTHON_REQUIRED_USE}"

RDEPEND="${PYTHON_DEPS}
	media-libs/libpng:0=
	media-libs/waffle
	sys-libs/zlib:=[${MULTILIB_USEDEP}]
	sys-process/procps
	X? ( x11-libs/libX11 )
	opengl? ( virtual/opengl )
	opengles? ( virtual/opengles )
	qt5? (
		dev-qt/qtcore:5
		dev-qt/qtgui:5[-gles2]
		dev-qt/qtnetwork:5
		dev-qt/qtwebkit:5
		dev-qt/qtwidgets:5[-gles2]
	)
	system-snappy? ( >=app-arch/snappy-1.1.1[${MULTILIB_USEDEP}] )
"
DEPEND="${RDEPEND}"

PATCHES=(
	"${FILESDIR}"/${PN}-8.0-glxtrace-only.patch
	"${FILESDIR}"/${PN}-8.0-disable-multiarch.patch
	"${FILESDIR}"/${PN}-9.0-docs-install.patch
	"${FILESDIR}"/${PN}-8.0-snappy-license.patch
	"${FILESDIR}"/0001-Fallback-to-NULL-platform-if-no-X.patch
	"${FILESDIR}"/${PN}-9.0-egl-environment.patch
	"${FILESDIR}"/${P}-libc-dlopen-glibc-2.34.patch
)

src_prepare() {
	cmake-utils_src_prepare

	# The apitrace code grubs around in the internal zlib structures.
	# We have to extract this header and clean it up to keep that working.
	# Do not be surprised if a zlib upgrade breaks things ...
	rm -rf "${S}"/thirdparty/{getopt,less,libpng,zlib,dxerr,directxtex,devcon} || die
	if use system-snappy ; then
		rm -rf "${S}"/thirdparty/snappy || die
	fi
}

src_configure() {
	my_configure() {
		local mycmakeargs=(
			-DENABLE_EGL=$(usex opengles)
			-DENABLE_STATIC_SNAPPY=$(usex !system-snappy)
		)
		if multilib_is_native_abi ; then
			mycmakeargs+=(
				-DENABLE_CLI=$(usex cli)
				-DENABLE_GUI=$(usex qt5)
				-DENABLE_X11=$(usex X)
				-DENABLE_WAFFLE=$(usex opengles)
			)
		else
			mycmakeargs+=(
				-DBUILD_LIB_ONLY=ON
				-DENABLE_CLI=OFF
				-DENABLE_GUI=OFF
			)
		fi
		cmake-utils_src_configure
	}

	multilib_parallel_foreach_abi my_configure
}

src_install() {
	cmake-multilib_src_install

	dosym egltrace.so /usr/$(get_libdir)/${PN}/wrappers/libGL.so
	dosym egltrace.so /usr/$(get_libdir)/${PN}/wrappers/libGL.so.1
	dosym egltrace.so /usr/$(get_libdir)/${PN}/wrappers/libGL.so.1.2

	rm docs/INSTALL.markdown || die
	dodoc docs/* README.markdown

	exeinto /usr/$(get_libdir)/${PN}/scripts
	doexe $(find scripts -type f -executable)

	echo "LDPATH=\"/usr/$(get_libdir)/${PN}/wrappers\"" > "${T}"/99${PN}
	doenvd "${T}"/99${PN}
}
