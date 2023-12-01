# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

SUBTREES=(
	.gn
	camera/build
	camera/common
	camera/features
	camera/gpu
	camera/include
	camera/mojo
	chromeos-config
	common-mk
	iioservice/libiioservice_ipc
	iioservice/mojo
	metrics
	ml_core
	mojo_service_manager
)

CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_SUBTREE="${SUBTREES[*]}"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD="1"

PLATFORM_SUBDIR="camera/common"

inherit cros-camera cros-constants cros-workon platform

DESCRIPTION="ChromeOS camera common libraries."

LICENSE="BSD-Google"
KEYWORDS="~*"

CAMERA_FEATURE_PREFIX="camera_feature_"
IUSE_FEATURE_FLAGS=(
	auto_framing
	diagnostics
	effects
	face_detection
	frame_annotator
	hdrnet
	portrait_mode
)
IUSE_PLATFORM_FLAGS=(
	ipu6
	ipu6ep
	ipu6se
	qualcomm_camx
)

# FEATURE and PLATFORM IUSE flags are passed to and used in BUILD.gn files.
IUSE="
	${IUSE_FEATURE_FLAGS[*]/#/${CAMERA_FEATURE_PREFIX}}
	${IUSE_PLATFORM_FLAGS[*]}
"

BDEPEND="virtual/pkgconfig"

RDEPEND="
	chromeos-base/chromeos-config-tools:=
	chromeos-base/cros-camera-android-deps:=
	chromeos-base/mojo_service_manager:=
	camera_feature_effects? ( dev-libs/ml-core:= )
	media-libs/cros-camera-libfs:=
	media-libs/libexif:=
	media-libs/libsync:=
	media-libs/minigbm:=
	virtual/libudev:=
	virtual/opengles:=
	x11-libs/libdrm:=
"

DEPEND="
	${RDEPEND}
	>=chromeos-base/metrics-0.0.1-r3152:=
	media-libs/cros-camera-libcamera_connector_headers:=
	media-libs/libyuv:=
	x11-base/xorg-proto:=
	x11-drivers/opengles-headers:=
"

src_configure() {
	cros_optimize_package_for_speed
	platform_src_configure
}

src_install() {
	local fuzzer_component_id="167281"
	platform_fuzzer_install "${S}"/OWNERS \
			"${OUT}"/camera_still_capture_processor_impl_fuzzer \
			--comp "${fuzzer_component_id}"
	platform_src_install
}

platform_pkg_test() {
	platform test_all
}
