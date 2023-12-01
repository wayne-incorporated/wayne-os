# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_SUBTREE="kexec-lite"
CROS_WORKON_OUTOFTREE_BUILD="1"
CROS_WORKON_INCREMENTAL_BUILD="1"

inherit cros-workon cros-rust

DESCRIPTION="Simple implementation of kexec-tools"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/kexec-lite"
LICENSE="BSD-Google"
KEYWORDS="~*"

DEPEND="dev-rust/third-party-crates-src:="

src_install() {
	dosbin "$(cros-rust_get_build_dir)"/kexec-lite
}
