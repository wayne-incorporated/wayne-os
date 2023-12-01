# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="555ec7ba06c797fadc6cb9c0db1fa7e0b08e7c0d"
CROS_WORKON_TREE=("92bdf273f63535712d4d991d9d195bb50db9d425" "8fd5cb688a5e1373afdc435818ac1d6d759eefe2")
CROS_WORKON_LOCALNAME="../platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_RUST_SUBDIR="io_uring"
CROS_WORKON_SUBDIRS_TO_COPY=("${CROS_RUST_SUBDIR}" .cargo)
CROS_WORKON_SUBTREE="${CROS_WORKON_SUBDIRS_TO_COPY[*]}"

# The version of this crate is pinned. See b/229016539 for details.
CROS_WORKON_MANUAL_UPREV="1"

# TODO: Enable tests on ARM once the emulator supports io_uring.
CROS_RUST_TEST_DIRECT_EXEC_ONLY="yes"

inherit cros-workon cros-rust

DESCRIPTION="Safe wrappers around the linux kernel's io_uring interface"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crosvm/+/HEAD/io_uring"
LICENSE="BSD-Google"
KEYWORDS="*"

DEPEND="
	chromeos-base/crosvm-base:=
	dev-rust/third-party-crates-src:=
	dev-rust/data_model:=
	dev-rust/sync:=
"
RDEPEND="${DEPEND}"

src_prepare() {
	cros-rust_src_prepare

	# Use the ChromeOS copy of base instead of the crosvm copy.
	sed -i 's/^base = /crosvm-base = /g' "${S}/Cargo.toml"
	find "${S}" -iname '*.rs' -type f -exec \
		sed -i -e 's/^use base/use crosvm_base/g' \
			-e 's/\([^[:alnum:]_]\)base::/\1crosvm_base::/g' -- {} +

	# Replace the version in the sources with the ebuild version.
	# ${FILESDIR}/chromeos-version.sh sets the minor version 50 ahead to avoid
	# colliding with the version included by path.
	if [[ "${PV}" != 9999 ]]; then
		sed -i 's/^version = .*$/version = "'"${PV}"'"/g' "${S}/Cargo.toml"
	fi
}

src_test() {
	# The io_uring implementation on kernels older than 5.10 was buggy so skip
	# them if we're running on one of those kernels.
	local cut_version="$(ver_cut 1-2 "$(uname -r)")"
	if ver_test "${cut_version}" -lt 5.10; then
		einfo "Skipping io_uring tests on kernel version < 5.10"
	else
		cros-rust_src_test
	fi
}
