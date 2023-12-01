# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "226f4d5fc18866d2b3d7927e69d9bb3492a6056f" "758b2cf0a8417ae154e01885f6a14bd46a0dabc5" "efe0d524649a8b9ec0f70ec09eeeabb92e900979" "bc1b04f26f0afbc10557f5c07fe35c34bb002f1d" "a667711e078cb6207565702a6f8d6be0a97709af" "5f52f55a4678653b15e0126bf489a8e105f32768")
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="../platform2"
# TODO(b/187784160): Avoid directly including headers from other packages.
CROS_WORKON_SUBTREE=".gn camera/build camera/common camera/hal/fake camera/include camera/mojo common-mk"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD="1"

PLATFORM_SUBDIR="camera/hal/fake"

inherit cros-camera cros-workon platform

DESCRIPTION="ChromeOS fake camera HAL."

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE=""

RDEPEND="
	chromeos-base/cros-camera-android-deps:=
	media-libs/libsync:=
	media-libs/libyuv:="
DEPEND="${RDEPEND}"
BDEPEND="virtual/pkgconfig:="
