# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "037981841cabd592d464eccc6bb92d7d3dfdebcc" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk libarc-attestation .gn"

PLATFORM_SUBDIR="libarc-attestation"

inherit cros-workon platform

DESCRIPTION="Utility for ARC Keymintd to perform Android Attestation and Remote Key Provisioning"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libarc-attestation/"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="test"

RDEPEND="
	chromeos-base/libhwsec:=[test?]
	>=chromeos-base/metrics-0.0.1-r3152:=
	chromeos-base/system_api:=
	"

DEPEND="
	${RDEPEND}
	"

platform_pkg_test() {
	platform test_all
}
