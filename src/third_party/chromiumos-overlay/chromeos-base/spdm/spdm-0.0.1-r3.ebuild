# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7
CROS_WORKON_COMMIT="27b237b3b705255cef7ae29476d6c980dcb9db36"
CROS_WORKON_TREE="21e025cab91f157db876fb805e4ff7d0ed3201d1"
CROS_WORKON_PROJECT="chromiumos/platform/spdm"
CROS_WORKON_LOCALNAME="platform/spdm"

inherit cros-workon cros-rust

DESCRIPTION="SPDM (Secure Protocol and Data Model) protocol implemented for secured messaging between userland and Google Security Chip."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/spdm/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	dev-rust/third-party-crates-src:=
"

DEPEND="${RDEPEND}"

src_unpack() {
	# Unpack both the project and dependency source code
	cros-workon_src_unpack
	cros-rust_src_unpack
}

src_install() {
	local build_dir="$(cros-rust_get_build_dir)"
	dolib.a "${build_dir}"/libspdm.a

	insinto /usr/include/spdm
	doins spdm.h
}

src_test() {
	cros-rust_src_test --workspace
}
