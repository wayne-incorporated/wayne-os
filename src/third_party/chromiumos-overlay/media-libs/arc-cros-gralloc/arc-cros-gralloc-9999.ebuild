# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
CROS_WORKON_PROJECT="chromiumos/platform/minigbm"
CROS_WORKON_LOCALNAME="../platform/minigbm"

inherit multilib-minimal arc-build cros-workon cros-sanitizers

DESCRIPTION="ChromeOS gralloc implementation"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/minigbm"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"

VIDEO_CARDS="amdgpu exynos intel marvell mediatek msm rockchip tegra virgl"
# shellcheck disable=SC2086
IUSE="$(printf 'video_cards_%s ' ${VIDEO_CARDS})"
MINI_GBM_PLATFORMS_USE=( mt8183 mt8186 mt8188g mt8192 mt8195 sc7280 )
IUSE+=" ${MINI_GBM_PLATFORMS_USE[*]/#/minigbm_platform_}"
IUSE+=" arcpp"

RDEPEND="
	!<media-libs/minigbm-0.0.1-r438
	x11-libs/arc-libdrm[${MULTILIB_USEDEP}]
"
DEPEND="
	${RDEPEND}
	video_cards_amdgpu? ( virtual/arc-opengles )
"

src_configure() {
	sanitizers-setup-env

	# Use arc-build base class to select the right compiler
	arc-build-select-clang

	# This packages uses -flto with gold, which doesn't support -Os
	# or -Oz. This produces a 76KB .so, so optimizing for size is
	# probably not a big deal.
	cros_optimize_package_for_speed

	BUILD_DIR="$(cros-workon_get_build_dir)"

	append-lfs-flags

	if [[ -n "${ARC_PLATFORM_SDK_VERSION}" ]]; then
		append-cppflags -DANDROID_API_LEVEL="${ARC_PLATFORM_SDK_VERSION}"
	fi

	# TODO(gsingh): use pkgconfig
	if use video_cards_intel; then
		export DRV_I915=1
		append-cppflags -DDRV_I915
		append-cppflags -DI915_SCANOUT_Y_TILED
	fi

	if use video_cards_rockchip; then
		export DRV_ROCKCHIP=1
		append-cppflags -DDRV_ROCKCHIP
	fi

	if use video_cards_mediatek; then
		use minigbm_platform_mt8183 && append-cppflags -DMTK_MT8183
		use minigbm_platform_mt8186 && append-cppflags -DMTK_MT8186
		use minigbm_platform_mt8188g && append-cppflags -DMTK_MT8188G
		use minigbm_platform_mt8192 && append-cppflags -DMTK_MT8192
		use minigbm_platform_mt8195 && append-cppflags -DMTK_MT8195
		export DRV_MEDIATEK=1
		append-cppflags -DDRV_MEDIATEK
	fi

	if use video_cards_msm; then
		use minigbm_platform_sc7280 && append-cppflags -DSC_7280
		export DRV_MSM=1
		append-cppflags -DDRV_MSM

		# On ARC++ UBWC causes visible green artifacts to appear during
		# window resize eg. during video playback.
		# This sould be removed once window resizing will handle UBWC
		# correctly. See b/195709707
		use arcpp && append-cppflags -DQCOM_DISABLE_COMPRESSED_NV12
	fi

	if use video_cards_amdgpu; then
		export DRV_AMDGPU=1
		append-cppflags -DDRV_AMDGPU -DHAVE_LIBDRM
	fi

	if use video_cards_virgl; then
		append-cppflags -DVIRTIO_GPU_NEXT
	fi

	multilib-minimal_src_configure
}

multilib_src_compile() {
	filter-flags "-DDRI_DRIVER_DIR=*"
	append-cppflags -DDRI_DRIVER_DIR="/vendor/$(get_libdir)/dri"
	export TARGET_DIR="${BUILD_DIR}/"

	# ARCVM doesn't need gralloc.cros.so because it uses
	# gralloc.minigbm_arcvm.so, which is built inside Android vendor image.
	if use arcpp; then
		emake -C "${S}/cros_gralloc"
	fi

	emake -C "${S}/cros_gralloc/gralloc0/tests/"
}

multilib_src_install() {
	if use arcpp; then
		exeinto "${ARC_PREFIX}/vendor/$(get_libdir)/hw/"
		doexe "${BUILD_DIR}"/gralloc.cros.so
	fi

	into "/usr/local/"
	# shellcheck disable=SC2154
	newbin "${BUILD_DIR}"/gralloctest "gralloctest_${ABI}"
}

multilib_src_install_all() {
	if use arcpp; then
		# Install cros_gralloc header files for arc-mali-* packages
		insinto "/usr/include/cros_gralloc"
		doins "${S}/cros_gralloc/cros_gralloc_handle.h"
	fi
}
