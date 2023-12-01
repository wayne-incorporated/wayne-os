# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="6c1274a47b76069dd2015fd111655a0e41e9f790"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "5b19eb81fa5ad0ca1af911923a1e2acb04b22975" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk biod .gn"

PLATFORM_SUBDIR="biod/mock-biod-test-deps"

inherit cros-workon platform

DESCRIPTION="biod test-only dbus policies. This package resides in test image only."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/biod/"

LICENSE="BSD-Google"
KEYWORDS="*"

DEPEND=""
RDEPEND="${DEPEND}"
BDEPEND=""

src_compile() {
	# We only install policy files here, no need to compile.
	:
}

src_install() {
	platform_src_install
}
