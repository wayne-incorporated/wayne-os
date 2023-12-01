# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_DESTDIR="${S}/platform2"
CROS_WORKON_SUBTREE="common-mk pciguard .gn"

PLATFORM_SUBDIR="pciguard"

inherit cros-workon platform user

DESCRIPTION="Chrome OS External PCI device security daemon"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/pciguard/"

LICENSE="BSD-Google"
SLOT=0
KEYWORDS="~*"

DEPEND="
	chromeos-base/session_manager-client:=
	chromeos-base/system_api:=
"

pkg_preinst() {
	enewuser pciguard
	enewgroup pciguard
	cros-workon_pkg_setup
}

platform_pkg_test() {
	platform test_all
}
