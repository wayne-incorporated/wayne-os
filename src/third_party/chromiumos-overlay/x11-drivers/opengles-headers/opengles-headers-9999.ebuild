# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/third_party/khronos"
CROS_WORKON_LOCALNAME="khronos"

inherit cros-workon cros-sanitizers

DESCRIPTION="OpenGL|ES headers."
HOMEPAGE="http://www.khronos.org/opengles/2_X/"
SRC_URI=""
LICENSE="SGI-B-2.0"
KEYWORDS="~*"
IUSE=""

DEPEND="
	x11-libs/libX11
	>=dev-util/opencl-headers-2021.04.29
	dev-util/spirv-headers
"
# Packages need to be in RDEPEND because we depend on the headers being present
# See http://go/ebuild-faq#dependency-types for detail
RDEPEND="
	${DEPEND}
"

src_configure() {
	sanitizers-setup-env
	default
}

src_install() {
	# headers
	insinto /usr/include/EGL
	doins "${S}/include/EGL/egl.h"
	doins "${S}/include/EGL/eglplatform.h"
	doins "${S}/include/EGL/eglext.h"
	insinto /usr/include/KHR
	doins "${S}/include/KHR/khrplatform.h"
	insinto /usr/include/GLES
	doins "${S}/include/GLES/gl.h"
	doins "${S}/include/GLES/glext.h"
	doins "${S}/include/GLES/glplatform.h"
	insinto /usr/include/GLES2
	doins "${S}/include/GLES2/gl2.h"
	doins "${S}/include/GLES2/gl2ext.h"
	doins "${S}/include/GLES2/gl2platform.h"
	insinto /usr/include/GLES3
	doins "${S}/include/GLES3/gl3.h"
	doins "${S}/include/GLES3/gl31.h"
	doins "${S}/include/GLES3/gl32.h"
	doins "${S}/include/GLES3/gl3platform.h"
}
