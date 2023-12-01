# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "2da9d61d19cec0757c1bf20a326e792be13ec50e" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
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
KEYWORDS="*"

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
