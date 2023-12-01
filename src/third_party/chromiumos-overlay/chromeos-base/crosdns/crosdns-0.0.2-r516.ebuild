# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "594cf0e9a121ef2fc158123ae1ee8a4a39934014" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_SUBTREE="common-mk crosdns .gn"

PLATFORM_SUBDIR="crosdns"

inherit cros-fuzzer cros-sanitizers cros-workon platform tmpfiles user

DESCRIPTION="Local hostname modifier service for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/crosdns"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"
IUSE="+seccomp asan fuzzer"

COMMON_DEPEND="
	chromeos-base/libbrillo:=[asan?,fuzzer?]
	chromeos-base/minijail:="

RDEPEND="${COMMON_DEPEND}"

DEPEND="
	${COMMON_DEPEND}
	chromeos-base/system_api:=[fuzzer?]"

src_install() {
	platform_src_install

	dotmpfiles tmpfiles.d/*.conf

	# fuzzer_component_id is unknown/unlisted
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/hosts_modifier_fuzzer
}

platform_pkg_test() {
	platform test_all
}

pkg_preinst() {
	enewuser "crosdns"
	enewgroup "crosdns"
}
