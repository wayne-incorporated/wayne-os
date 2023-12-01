# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/media-libs/waffle/waffle-1.3.0.ebuild,v 1.2 2013/12/28 11:29:05 vapier Exp $

EAPI=6

inherit cmake-utils

DESCRIPTION="Library that allows selection of GL API and of window system at runtime"
HOMEPAGE="http://www.waffle-gl.org"
# TODO(fjhenigman): merge github fork into main project and change SRC_URI back to a release from there
MY_V="null2"
# TODO(ihf): Remove the -r1 when reving the next MY_V archive. Also notice that the waffle-1.6.0-r1.tar.gz
# to waffle-1.6.0-r6.tar.gz tarballs on GS are identical.
SRC_URI="https://github.com/fjhenigman/waffle/archive/${MY_V}.tar.gz -> ${P}-r1.tar.gz"
S="${WORKDIR}/${PN}-${MY_V}"
LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"
IUSE="doc examples gbm opengl opengles test wayland X"

# Note: Chrome OS currently uses the following USE flags:
#   opengl   => GLX and OpenGL
#   opengles => EGL (X11 and/or gbm) and OpenGL ES
# TODO: sync USE flags with upstream gentoo: crbug.com/375298

REQUIRED_USE="
	|| ( opengl opengles )
	opengl? ( X )
	|| ( X gbm wayland )
"

RDEPEND="
	opengl? ( virtual/opengl )
	opengles? ( virtual/opengles )
	X? (
		x11-libs/libX11
		x11-libs/libxcb
	)
	gbm? ( || ( (
			media-libs/mesa[gbm]
			virtual/udev
		) media-libs/minigbm )
	)
	wayland? ( >=dev-libs/wayland-1.0 )
"

DEPEND="${RDEPEND}
	opengl? ( x11-proto/glproto )
	x11-drivers/opengles-headers
	x11-libs/libX11
	X? ( x11-proto/xcb-proto )
	doc? (
		dev-libs/libxslt
		app-text/docbook-xml-dtd:4.2
	)
"

PATCHES=(
	"${FILESDIR}"/0001-Support-oak-board.patch
	"${FILESDIR}"/0001-null-use-EGL_DEFAULT_DISPLAY.patch
	"${FILESDIR}"/0002-null-Fix-null-code-to-work-with-Mesa-11.0.2.patch
	"${FILESDIR}"/0003-eglChooseConfig.patch
	"${FILESDIR}"/0004-Pass-dma_buf-import-modifiers-if-driver-supports-thi.patch
	"${FILESDIR}"/0005-Add-support-for-EXT_image_flush_external-extension.patch
	"${FILESDIR}"/0006-Transition-to-the-official-DMA-BUF-import-modifier-t.patch
	"${FILESDIR}"/0007-Use-drmModeAddFB2WithModifiers-incase-of-modifiers.patch
)

src_configure() {
	if use opengles && use X; then
		waffle_has_x11_egl=ON
	else
		waffle_has_x11_egl=OFF
	fi
	local mycmakeargs=(
		-Dwaffle_has_glx=$(usex opengl)
		-Dwaffle_has_x11_egl=$waffle_has_x11_egl
		-Dwaffle_build_examples=$(usex examples)
		-Dwaffle_build_manpages=$(usex doc)
		-Dwaffle_has_gbm=$(usex gbm)
		-Dwaffle_build_tests=$(usex test)
		-Dwaffle_has_wayland=$(usex wayland)
	)

	tc-export CC CXX # crbug.com/471450

	cmake-utils_src_configure
}

src_test() {
	emake -C "${CMAKE_BUILD_DIR}" check
}
