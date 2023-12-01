# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "ac72d23ce2b0fa0b6c406753935fbe20ca5df978" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD="1"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk printscanmgr .gn"

PLATFORM_SUBDIR="printscanmgr"

inherit cros-workon platform user

DESCRIPTION="Chrome OS printing and scanning daemon"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/printscanmgr/"
LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="fuzzer"

COMMON_DEPEND="
	chromeos-base/minijail:=
"

RDEPEND="${COMMON_DEPEND}
	"

DEPEND="${COMMON_DEPEND}
	chromeos-base/system_api:=[fuzzer?]
	sys-apps/dbus:="

pkg_preinst() {
	enewuser printscanmgr
	enewgroup printscanmgr
}

src_install() {
	platform_src_install

	# Install fuzzers.
	local fuzzer_component_id="167231"
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/cups_uri_helper_utils_fuzzer \
		--comp "${fuzzer_component_id}"
}

platform_pkg_test() {
	platform test_all
}
