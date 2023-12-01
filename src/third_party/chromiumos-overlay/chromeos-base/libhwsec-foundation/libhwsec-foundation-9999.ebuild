# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk metrics libhwsec-foundation .gn"

PLATFORM_SUBDIR="libhwsec-foundation"

inherit cros-workon platform tmpfiles

DESCRIPTION="Crypto and utility functions used in TPM related daemons."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libhwsec-foundation/"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="profiling test tpm tpm_dynamic tpm2"

DEPEND="
	>=chromeos-base/metrics-0.0.1-r3152
	chromeos-base/system_api
	chromeos-base/tpm_manager-client
	"

RDEPEND="${DEPEND}"

src_install() {
	platform_src_install

	# Install tmpfiles.d for creating dir for profiling data.
	if use profiling; then
		dotmpfiles profiling/tmpfiles.d/profiling.conf
	fi

	local fuzzer_component_id="1188704"
	platform_fuzzer_install "${S}"/OWNERS \
		"${OUT}"/libhwsec_foundation_rsa_oaep_decrypt_fuzzer \
		--comp "${fuzzer_component_id}" \
		fuzzers/testdata/*
}

platform_pkg_test() {
	platform test_all
}
