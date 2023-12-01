# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6
CROS_WORKON_COMMIT="94106a2845911104895c50aa5d70c6e5fc8972fc"
CROS_WORKON_TREE="ce474b6cace8aef336c8c4b13a35f0fdcdf28168"
CROS_WORKON_PROJECT="chromiumos/platform/drm-tests"
CROS_WORKON_LOCALNAME="platform/drm-tests"

inherit cros-sanitizers cros-workon toolchain-funcs

DESCRIPTION="Chrome OS DRM Tests"

HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/drm-tests/"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="
	v4lplugin
	vulkan
	"

RDEPEND="virtual/opengles
	|| ( media-libs/mesa[gbm] media-libs/minigbm )
	media-libs/libsync
	v4lplugin? ( media-libs/libv4lplugins )
	vulkan? (
		media-libs/vulkan-loader
		virtual/vulkan-icd
	)"
DEPEND="${RDEPEND}
	x11-drivers/opengles-headers
	dev-libs/openssl
	dev-util/vulkan-headers"

src_configure() {
	sanitizers-setup-env
	default
}

src_compile() {
	tc-export CC
	if use v4lplugin; then
		einfo "- Using libv4l2plugin"
		append-flags "-DUSE_V4LPLUGIN"
	fi
	emake USE_VULKAN="$(usex vulkan 1 0)" USE_V4LPLUGIN="$(usex v4lplugin 1 0)"
}

src_install() {
	cd build-opt-local || return
	into /usr/local
	dobin atomictest \
		drm_cursor_test \
		dmabuf_test \
		gamma_test \
		gbmtest \
		linear_bo_test \
		mali_stats \
		mapped_access_perf_test \
		mapped_texture_test \
		mmap_test \
		mtk_dram_tool \
		null_platform_test \
		plane_test \
		synctest swrast_test \
		udmabuf_create_test \
		v4l2_stateful_decoder \
		v4l2_stateful_encoder\
		yuv_to_rgb_test

	if use vulkan; then
		dobin vk_glow
	fi
}
