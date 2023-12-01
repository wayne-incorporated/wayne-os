# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="6c1274a47b76069dd2015fd111655a0e41e9f790"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "107a6cd74aed39f6f893462ca9099d2f3373347c" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
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
KEYWORDS="*"
IUSE=""

platform_pkg_test() {
	platform test_all
}
