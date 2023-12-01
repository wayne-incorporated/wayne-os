# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "673cfef9da87bf9383539f3682af6091efae418c" "b62ae50ed547d76feb94710f8c187f5a3f52bc84" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD="1"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
# TODO(crbug.com/809389): Avoid directly including headers from other packages.
CROS_WORKON_SUBTREE="common-mk lorgnette metrics .gn"

PLATFORM_SUBDIR="lorgnette"

inherit cros-workon platform user udev

DESCRIPTION="Document Scanning service for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/lorgnette/"
LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="test"

COMMON_DEPEND="
	>=chromeos-base/metrics-0.0.1-r3152:=
	media-libs/libpng:=
	media-gfx/sane-airscan:=
	media-gfx/sane-backends:=
	virtual/jpeg:0=
	virtual/libusb:1
"

RDEPEND="${COMMON_DEPEND}
	chromeos-base/minijail
	test? (
		chromeos-base/sane-backends-test
		media-gfx/perceptualdiff:=
	)
"

DEPEND="${COMMON_DEPEND}
	chromeos-base/permission_broker-client:=
	chromeos-base/system_api:=
"

pkg_preinst() {
	enewgroup ippusb
	enewgroup usbprinter
}

src_install() {
	platform_src_install
	udev_dorules udev/*.rules
}

platform_pkg_test() {
	platform_test "run" "${OUT}/lorgnette_unittest"
}
