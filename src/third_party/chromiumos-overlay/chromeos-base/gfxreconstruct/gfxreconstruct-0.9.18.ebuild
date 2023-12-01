# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake-utils flag-o-matic unpacker

DESCRIPTION="Vulkan API Capture and Replay Tools"
HOMEPAGE="https://github.com/LunarG/gfxreconstruct"
GIT_HASH="a4ad90bc1d466f0bb902db6ae321f28362c16429"
SRC_URI="https://github.com/LunarG/gfxreconstruct/archive/${GIT_HASH}.tar.gz -> gfxreconstruct-${GIT_HASH}.tar.gz"

LICENSE="MIT"
KEYWORDS="*"
IUSE=""
SLOT="0"

S="${WORKDIR}/gfxreconstruct-${GIT_HASH}"

RDEPEND="
	x11-libs/libxcb
	sys-libs/zlib
	app-arch/zstd
"
DEPEND="
	${RDEPEND}
	>=dev-util/vulkan-headers-1.3.239
	x11-libs/xcb-util-keysyms
"

PATCHES=(
	"${FILESDIR}/0001-ChromeOS-headers.patch"
	"${FILESDIR}/0002-Fix-library-path-in-layer-manifest.patch"
	"${FILESDIR}/0003-Fix-subprocess.capture_output-in-python3.6.patch"
)

src_prepare() {
	cmake-utils_src_prepare
}

src_configure() {
	cros_enable_cxx_exceptions
	cmake-utils_src_configure
}

src_compile() {
	cmake-utils_src_compile
}

src_install() {
	local OUTDIR="${WORKDIR}/gfxreconstruct-${PV}_build"
	local TOOLSDIR="${OUTDIR}/tools"

	dobin "${TOOLSDIR}/replay/gfxrecon-replay"
	dobin "${TOOLSDIR}/compress/gfxrecon-compress"
	dobin "${TOOLSDIR}/optimize/gfxrecon-optimize"
	dobin "${TOOLSDIR}/extract/gfxrecon-extract"
	dobin "${TOOLSDIR}/convert/gfxrecon-convert"
	dobin "${TOOLSDIR}/info/gfxrecon-info"
	dobin "${TOOLSDIR}/gfxrecon/gfxrecon.py"
	dobin "${TOOLSDIR}/capture/gfxrecon-capture.py"
	dobin "${TOOLSDIR}/capture-vulkan/gfxrecon-capture-vulkan.py"

	dolib.so "${OUTDIR}/layer/libVkLayer_gfxreconstruct.so"
	insinto /usr/share/vulkan/explicit_layer.d
	doins "${OUTDIR}/layer/VkLayer_gfxreconstruct.json"
}
