# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk net-base .gn"

PLATFORM_SUBDIR="net-base"

inherit cros-workon libchrome platform

DESCRIPTION="Networking primitive library"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/net-base/"
LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

platform_pkg_test() {
	platform test_all
}
