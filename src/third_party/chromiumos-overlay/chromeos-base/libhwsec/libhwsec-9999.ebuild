# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk libcrossystem libhwsec libhwsec-foundation metrics tpm_manager tpm2-simulator trunks .gn"

PLATFORM_SUBDIR="libhwsec"

inherit cros-workon platform

DESCRIPTION="Crypto and utility functions used in TPM related daemons."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libhwsec/"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="test fuzzer tpm tpm2 tpm_dynamic"

COMMON_DEPEND="
	chromeos-base/chromeos-ec-headers:=
	chromeos-base/libhwsec-foundation:=
	chromeos-base/metrics:=
	chromeos-base/system_api:=
	chromeos-base/tpm_manager-client:=
	chromeos-base/libcrossystem:=
	dev-libs/openssl:0=
	dev-libs/flatbuffers:=
	tpm2? (
		chromeos-base/pinweaver:=
		chromeos-base/trunks:=[test?]
	)
	tpm? ( app-crypt/trousers:= )
	fuzzer? (
		app-crypt/trousers:=
		chromeos-base/trunks:=
	)
	test? (
		app-crypt/trousers:=
		chromeos-base/pinweaver:=
		chromeos-base/trunks:=[test]
		chromeos-base/tpm2-simulator:=[test]
	)
"

RDEPEND="${COMMON_DEPEND}"
DEPEND="${COMMON_DEPEND}"

platform_pkg_test() {
	platform test_all
}

src_install() {
	platform_src_install

	local fuzzer_component_id="1188704"

	platform_fuzzer_install "${S}"/OWNERS \
		"${OUT}"/libhwsec_tpm1_cmk_migration_parser_fuzzer \
		--comp "${fuzzer_component_id}"
}
