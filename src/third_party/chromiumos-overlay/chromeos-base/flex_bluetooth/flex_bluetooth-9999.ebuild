# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_DESTDIR="${S}/platform2"
CROS_WORKON_SUBTREE="common-mk flex_bluetooth .gn"

PLATFORM_SUBDIR="flex_bluetooth"

inherit cros-workon platform

DESCRIPTION="Apply (Floss) Bluetooth overrides for ChromeOS Flex"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/flex_bluetooth"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

platform_pkg_test() {
	platform_test "run" "${OUT}/flex_bluetooth_overrides_test"
}
