# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="6c1274a47b76069dd2015fd111655a0e41e9f790"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "8a7b19f25ed5d2e97685287f36d4f5735bb07a39" "b62ae50ed547d76feb94710f8c187f5a3f52bc84" "107a6cd74aed39f6f893462ca9099d2f3373347c" "f74f32e76e5f0463b8473657c06db9cbb493b16a" "b26b88225b688c83bedd83bace447f9ea901cf00" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk dns-proxy metrics net-base shill/dbus/client shill/net .gn"

PLATFORM_SUBDIR="dns-proxy"

inherit cros-workon platform user

DESCRIPTION="A daemon that provides DNS proxying services."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/dns-proxy/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"

COMMON_DEPEND="
	chromeos-base/metrics:=
	chromeos-base/minijail:=
	chromeos-base/net-base:=
	chromeos-base/patchpanel:=
	chromeos-base/patchpanel-client:=
	chromeos-base/session_manager-client:=
	chromeos-base/shill-dbus-client:=
	chromeos-base/shill-net:=
	dev-libs/protobuf:=
	sys-apps/dbus:=
	net-misc/curl:=
"
RDEPEND="${COMMON_DEPEND}"
DEPEND="
	${COMMON_DEPEND}
	chromeos-base/permission_broker-client:=
"

pkg_preinst() {
	enewuser "dns-proxy"
	enewgroup "dns-proxy"
}

src_install() {
	platform_src_install

	local fuzzer_component_id="156085"
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/ares_client_fuzzer \
		--comp "${fuzzer_component_id}"
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/doh_curl_client_fuzzer \
		--comp "${fuzzer_component_id}"
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/resolver_fuzzer \
		--comp "${fuzzer_component_id}"
}

platform_pkg_test() {
	platform test_all
}
