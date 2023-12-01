# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

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
KEYWORDS="~*"

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
