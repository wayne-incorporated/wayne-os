# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="278c84bfd03995394a1639e88c77784df4bf7afb"
CROS_WORKON_TREE=("29436f435fc120ef86db06a26dfa522c30e45483" "fa91eb24f5d1f5d37f2b8765977fb8a265c0f9a6")
CROS_WORKON_LOCALNAME="../platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_RUST_SUBDIR="serde_keyvalue/serde_keyvalue_derive"
CROS_WORKON_SUBDIRS_TO_COPY=("${CROS_RUST_SUBDIR}" .cargo)
CROS_WORKON_SUBTREE="${CROS_WORKON_SUBDIRS_TO_COPY[*]}"

# The version of this crate is pinned. See b/229016539 for details.
CROS_WORKON_MANUAL_UPREV="1"

inherit cros-workon cros-rust

DESCRIPTION="derive macros for serde_keyvalue"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crosvm/+/HEAD/serde_keyvalue/serde_keyvalue_derive"
LICENSE="BSD-Google"
KEYWORDS="*"

DEPEND="
	dev-rust/third-party-crates-src:=
"
RDEPEND="${DEPEND}"

src_prepare() {
	cros-rust_src_prepare

	# Replace the version in the sources with the ebuild version.
	# ${FILESDIR}/chromeos-version.sh sets the minor version 50 ahead to avoid
	# colliding with the version included by path.
	if [[ "${PV}" != 9999 ]]; then
		sed -i 's/^version = .*$/version = "'"${PV}"'"/g' "${S}/Cargo.toml"
	fi
}
