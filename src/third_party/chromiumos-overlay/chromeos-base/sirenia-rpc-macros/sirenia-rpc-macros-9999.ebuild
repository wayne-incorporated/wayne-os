# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This is used to break a circular dependency caused by tests.
CROS_RUST_REMOVE_DEV_DEPS=1
CROS_RUST_SUBDIR="sirenia/libsirenia/sirenia-rpc-macros"

CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"

inherit cros-workon cros-rust

DESCRIPTION="Macros for generating the RPC implementation for Sirenia."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/sirenia/libsirenia/sirenia-rpc-macros"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

DEPEND="dev-rust/third-party-crates-src:="
# (crbug.com/1182669): build-time only deps need to be in RDEPEND so they are pulled in when
# installing binpkgs since the full source tree is required to use the crate.
RDEPEND="${DEPEND}"

# cros-rust_src_compile isn't used because it builds the unit tests.
src_compile() {
	ecargo_build
}

# The tests are run in libsirenia since they depend on libsirenia which depends
# on this ebuild.
src_test() { :; }
