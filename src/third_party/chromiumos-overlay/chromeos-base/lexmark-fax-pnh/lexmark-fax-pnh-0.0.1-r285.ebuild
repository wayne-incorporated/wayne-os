# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT=("e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd" "d80cce020cf6bd6c29c4008beeffd9635a82173d")
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "6ff72b1c92c1d9ebb9d45ae248132b5d803e7122")
CROS_WORKON_LOCALNAME=("platform2" "third_party/lexmark-fax-pnh")
CROS_WORKON_EGIT_BRANCH=("main" "master")
CROS_WORKON_PROJECT=("chromiumos/platform2" "chromiumos/third_party/lexmark-fax-pnh")
CROS_WORKON_DESTDIR=("${S}/platform2" "${S}/platform2/lexmark-fax-pnh")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_SUBTREE=("common-mk .gn" "")

PLATFORM_SUBDIR="lexmark-fax-pnh"

inherit cros-workon platform

DESCRIPTION="ChromeOS implementation of the Lexmark fax-pnh-filter"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/lexmark-fax-pnh/"

LICENSE="MPL-2.0"
KEYWORDS="*"

IUSE=""

RDEPEND="
	net-print/cups
"
DEPEND="${RDEPEND}"

platform_pkg_test() {
	platform_test "run" "${OUT}/token_replacer_testrunner"
}

src_install() {
	platform_src_install

	exeinto /usr/libexec/cups/filter
	doexe "${OUT}"/fax-pnh-filter
}
