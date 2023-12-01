# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "226f4d5fc18866d2b3d7927e69d9bb3492a6056f" "6afa7602f9bb1fa5904a2d953e4d7a6331846119" "5f52f55a4678653b15e0126bf489a8e105f32768")
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_SUBTREE=".gn camera/build camera/android common-mk"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD="1"

PLATFORM_SUBDIR="camera/android"

inherit cros-workon platform

DESCRIPTION="Android dependencies needed by cros-camera service and vendor HALs"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	!media-libs/cros-camera-android-headers
	!media-libs/cros-camera-libcamera_client
	!media-libs/cros-camera-libcamera_metadata
"

src_configure() {
	cros_optimize_package_for_speed
	platform_src_configure
}
