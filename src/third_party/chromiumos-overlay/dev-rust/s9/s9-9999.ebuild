# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_RUST_SUBDIR="vm_tools/9s"

CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"

CROS_RUST_CRATE_NAME="p9s"

inherit cros-workon cros-rust

DESCRIPTION="Server binary for the 9P file system protocol"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/vm_tools/9s/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"
IUSE="test"

RDEPEND="
	!<chromeos-base/crosvm-0.0.1-r260
	!dev-rust/9s
"
DEPEND="
	dev-rust/third-party-crates-src:=
	dev-rust/libchromeos:=
	dev-rust/p9:=
"

src_install() {
	newbin "$(cros-rust_get_build_dir)/p9s" 9s

	insinto /usr/share/policy
	newins "seccomp/9s-seccomp-${ARCH}.policy" 9s-seccomp.policy
}
