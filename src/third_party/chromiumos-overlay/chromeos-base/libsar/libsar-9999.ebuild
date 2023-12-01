# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD="1"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk chromeos-config libsar .gn"

PLATFORM_SUBDIR="libsar"

inherit cros-workon platform

DESCRIPTION="Library to support SAR sensor like Semtech SX93xx components for ChromiumOS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libsar"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

COMMON_DEPEND="
	chromeos-base/chromeos-config-tools:="
RDEPEND="${COMMON_DEPEND}"
DEPEND="${COMMON_DEPEND}"

platform_pkg_test() {
	platform test_all
}
