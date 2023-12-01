# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_DESTDIR="${S}/platform2"
CROS_WORKON_SUBTREE="common-mk flex_id .gn"

PLATFORM_SUBDIR="flex_id"

inherit cros-workon platform

DESCRIPTION="Utility to generate Flex ID for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/flex_id"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

RDEPEND="!chromeos-base/client_id"

src_install() {
	platform_src_install

	dobin "${OUT}"/flex_id_tool
}

platform_pkg_test() {
	platform_test "run" "${OUT}/flex_id_test"
}
