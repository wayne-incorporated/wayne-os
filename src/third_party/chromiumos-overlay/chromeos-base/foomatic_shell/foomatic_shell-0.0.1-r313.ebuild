# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "97378d3cd982a2aeddbde7e641cd320800b47209" "b62ae50ed547d76feb94710f8c187f5a3f52bc84" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk foomatic_shell metrics .gn"

PLATFORM_SUBDIR="foomatic_shell"

inherit cros-workon platform

DESCRIPTION="Mini shell used by foomatic-rip to execute scripts in PPD files."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/foomatic_shell/"

LICENSE="BSD-Google"
KEYWORDS="*"

RDEPEND="chromeos-base/metrics:="
DEPEND="${RDEPEND}"

src_install() {
	platform_src_install

	dobin "${OUT}/foomatic_shell"

	# Install fuzzer
	local fuzzer_component_id="167231"
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/foomatic_shell_fuzzer \
		--comp "${fuzzer_component_id}"
}

platform_pkg_test() {
	platform_test "run" "${OUT}/foomatic_shell_test"
}
