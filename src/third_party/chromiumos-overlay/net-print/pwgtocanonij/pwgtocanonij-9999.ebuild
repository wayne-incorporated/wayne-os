# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_INCREMENTAL_BUILD="1"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_SUBTREE="common-mk pwgtocanonij .gn"
CROS_WORKON_OUTOFTREE_BUILD=1

PLATFORM_SUBDIR="pwgtocanonij"

inherit cros-workon platform

DESCRIPTION="Canon print filters for CUPS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/pwgtocanonij/"
LICENSE="BSD-Google"
KEYWORDS="~*"

RDEPEND="net-print/cups"

DEPEND="${RDEPEND}"

src_install() {
	exeinto /usr/libexec/cups/filter
	doexe "${OUT}"/pwgtocanonij
}

platform_pkg_test() {
	platform test_all
}
