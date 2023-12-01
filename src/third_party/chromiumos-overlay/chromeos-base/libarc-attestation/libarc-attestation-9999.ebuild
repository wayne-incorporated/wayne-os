# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

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
KEYWORDS="~*"
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
