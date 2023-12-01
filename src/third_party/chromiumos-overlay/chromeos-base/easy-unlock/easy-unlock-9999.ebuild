# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_USE_VCSID=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk easy-unlock .gn"

PLATFORM_SUBDIR="easy-unlock"

inherit cros-workon platform user

DESCRIPTION="Service for supporting Easy Unlock in Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/easy-unlock/"
LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"
IUSE=""

COMMON_DEPEND="
	chromeos-base/easy-unlock-crypto:=
"

RDEPEND="${COMMON_DEPEND}"

DEPEND="
	${COMMON_DEPEND}
	chromeos-base/system_api:=
"

pkg_preinst() {
	enewuser easy-unlock
	enewgroup easy-unlock
}

platform_pkg_test() {
	platform test_all
}
