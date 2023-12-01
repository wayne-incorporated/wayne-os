# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="6c1274a47b76069dd2015fd111655a0e41e9f790"
CROS_WORKON_TREE=("f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "226f4d5fc18866d2b3d7927e69d9bb3492a6056f" "758b2cf0a8417ae154e01885f6a14bd46a0dabc5" "b4fa4d69a34561282920c9063fa86fdeefba661d" "56d11be3eee2e1ae4822f70f73b6e8cc7a4082c8" "bc1b04f26f0afbc10557f5c07fe35c34bb002f1d" "a667711e078cb6207565702a6f8d6be0a97709af" "57dcbeb4c073f8510e8b35cecdf20b000cab5fdb" "5f52f55a4678653b15e0126bf489a8e105f32768" "1e601fb1df98e9ea9f5803aeb50bd6fbec835a2a" "e40ac435946a5417104d844a323350d04e9d3b2e" "b62ae50ed547d76feb94710f8c187f5a3f52bc84" "fa0665bfd3f2b980857d473daf71e5c489e2b28e" "66d9ece0c55ff21826b4962ffd402f0927467387")
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
KEYWORDS="*"

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
