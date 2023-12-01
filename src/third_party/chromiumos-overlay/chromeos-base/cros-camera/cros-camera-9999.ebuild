# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

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
KEYWORDS="~*"
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
