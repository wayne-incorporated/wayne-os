# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="6c1274a47b76069dd2015fd111655a0e41e9f790"
CROS_WORKON_TREE=("f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "226f4d5fc18866d2b3d7927e69d9bb3492a6056f" "758b2cf0a8417ae154e01885f6a14bd46a0dabc5" "b4fa4d69a34561282920c9063fa86fdeefba661d" "56d11be3eee2e1ae4822f70f73b6e8cc7a4082c8" "c4c26e2590704f58985d3b7377d6ce97a8f262ae" "47d639d3bb9e6f23a78599265f8cd349c015e572" "bc1b04f26f0afbc10557f5c07fe35c34bb002f1d" "a667711e078cb6207565702a6f8d6be0a97709af" "5f52f55a4678653b15e0126bf489a8e105f32768" "fa0665bfd3f2b980857d473daf71e5c489e2b28e")
SUBTREES=(
	.gn
	camera/build
	camera/common
	camera/features
	camera/gpu
	# TODO(crbug.com/914263): camera/hal is unnecessary for this build but
	# is workaround for unexpected sandbox behavior.
	camera/hal
	camera/hal_adapter
	camera/include
	camera/mojo
	common-mk
	ml_core
)

CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_SUBTREE="${SUBTREES[*]}"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD="1"

PLATFORM_SUBDIR="camera/hal_adapter"

inherit cros-camera cros-constants cros-workon platform tmpfiles user udev

DESCRIPTION="ChromeOS camera service. The service is in charge of accessing
camera device. It uses unix domain socket to build a synchronous channel."

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="cheets camera_feature_face_detection arcvm -libcamera"

BDEPEND="virtual/pkgconfig"

RDEPEND="
	>=chromeos-base/cros-camera-libs-0.0.1-r34:=
	chromeos-base/cros-camera-android-deps:=
	chromeos-base/system_api:=
	media-libs/cros-camera-hal-usb:=
	media-libs/libsync:=
	media-libs/libyuv:=
	libcamera? ( media-libs/libcamera )
	!libcamera? (
		virtual/cros-camera-hal
		virtual/cros-camera-hal-configs
	)"

DEPEND="${RDEPEND}
	chromeos-base/dlcservice-client:=
	>=chromeos-base/metrics-0.0.1-r3152:=
	media-libs/minigbm:=
	x11-drivers/opengles-headers:=
	x11-libs/libdrm:="

src_configure() {
	cros_optimize_package_for_speed
	platform_src_configure
}

src_install() {
	platform_src_install
	udev_dorules udev/99-camera.rules
	dotmpfiles tmpfiles.d/*.conf
}

pkg_preinst() {
	enewuser "arc-camera"
	enewgroup "arc-camera"
	enewgroup "camera"
}
