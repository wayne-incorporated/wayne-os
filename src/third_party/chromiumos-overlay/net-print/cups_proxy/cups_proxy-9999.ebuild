# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk cups_proxy .gn"

PLATFORM_SUBDIR="cups_proxy"

inherit tmpfiles cros-workon platform user

DESCRIPTION="CUPS Proxy Daemon for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/cups_proxy/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
IUSE=""

RDEPEND="
	chromeos-base/libbrillo:=
	net-libs/libmicrohttpd:=
	"

DEPEND="${RDEPEND}
	"

pkg_preinst() {
	enewuser cups-proxy
	enewgroup cups-proxy
}

platform_pkg_test() {
	platform test_all
}
