# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk chromeos-config libcrossystem libec runtime_probe .gn"

PLATFORM_SUBDIR="runtime_probe"

inherit cros-workon cros-unibuild platform user udev

DESCRIPTION="Runtime probing on device componenets."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/runtime_probe/"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="asan fuzzer"

COMMON_DEPEND="
	chromeos-base/chromeos-config-tools:=
	chromeos-base/cros-camera-libs:=
	chromeos-base/debugd-client:=
	chromeos-base/libcrossystem:=
	chromeos-base/libec:=
	chromeos-base/shill-client:=
	dev-libs/libpcre:=
	media-libs/minigbm:=
"

RDEPEND="${COMMON_DEPEND}"

DEPEND="${COMMON_DEPEND}
	chromeos-base/system_api:=[fuzzer?]
"

pkg_preinst() {
	# Create user and group for runtime_probe
	enewuser "runtime_probe"
	enewgroup "cros_ec-access"
	enewgroup "runtime_probe"
}

src_install() {
	platform_src_install

	# Install udev rules.
	udev_dorules udev/*.rules

	local fuzzer
	for fuzzer in "${OUT}"/*_fuzzer; do
		local fuzzer_component_id="606088"
		platform_fuzzer_install "${S}"/OWNERS "${fuzzer}" \
			--comp "${fuzzer_component_id}"
	done
}

platform_pkg_test() {
	platform test_all
}
