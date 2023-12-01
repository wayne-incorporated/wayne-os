# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="6c1274a47b76069dd2015fd111655a0e41e9f790"
CROS_WORKON_TREE=("f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "226f4d5fc18866d2b3d7927e69d9bb3492a6056f" "758b2cf0a8417ae154e01885f6a14bd46a0dabc5" "bc1b04f26f0afbc10557f5c07fe35c34bb002f1d" "b4fa4d69a34561282920c9063fa86fdeefba661d" "56d11be3eee2e1ae4822f70f73b6e8cc7a4082c8" "a667711e078cb6207565702a6f8d6be0a97709af" "57dcbeb4c073f8510e8b35cecdf20b000cab5fdb" "5f52f55a4678653b15e0126bf489a8e105f32768" "1e601fb1df98e9ea9f5803aeb50bd6fbec835a2a" "e40ac435946a5417104d844a323350d04e9d3b2e" "fa0665bfd3f2b980857d473daf71e5c489e2b28e")
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_SUBTREE=".gn camera/build camera/common camera/include camera/features camera/gpu camera/mojo chromeos-config common-mk iioservice/libiioservice_ipc iioservice/mojo ml_core"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD="1"

PLATFORM_SUBDIR="camera/features/frame_annotator/libs"

inherit cros-workon platform

DESCRIPTION="ChromeOS Camera Frame Annotator Library"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

BDEPEND="virtual/pkgconfig"

RDEPEND="
	media-libs/libyuv:=
	media-libs/skia:=
	chromeos-base/metrics:=
	chromeos-base/cros-camera-libs:=
"
DEPEND="
	x11-drivers/opengles-headers:=
	${RDEPEND}
"

src_configure() {
	cros_optimize_package_for_speed
	platform_src_configure
}
