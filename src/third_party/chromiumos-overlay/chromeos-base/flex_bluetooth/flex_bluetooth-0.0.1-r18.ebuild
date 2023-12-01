# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7
CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "9ff890b3d92a8f707de8a1911defc04326b2de28" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_DESTDIR="${S}/platform2"
CROS_WORKON_SUBTREE="common-mk flex_bluetooth .gn"

PLATFORM_SUBDIR="flex_bluetooth"

inherit cros-workon platform

DESCRIPTION="Apply (Floss) Bluetooth overrides for ChromeOS Flex"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/flex_bluetooth"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE=""

platform_pkg_test() {
	platform_test "run" "${OUT}/flex_bluetooth_overrides_test"
}
