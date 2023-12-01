# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_RUST_PREINSTALLED_REGISTRY_CRATE=1
CROS_RUST_REMOVE_DEV_DEPS=1

inherit cros-rust

DESCRIPTION='Generate Rust register maps ("struct"s) from SVD files'
HOMEPAGE='https://crates.io/crates/svd2rust'

LICENSE="|| ( MIT Apache-2.0 )"
SLOT="${PV}/${PR}"
KEYWORDS="*"

DEPEND="dev-rust/third-party-crates-src:="
RDEPEND="${DEPEND}"

src_compile() {
	ecargo_build
	use test && ecargo_test --no-run
}

src_install() {
	dobin "${CARGO_TARGET_DIR}/${CHOST}/release/svd2rust"
}

src_configure() {
	cros-rust_src_configure

	# svd2rust uses proc-macro2, which decides at runtime whether to use
	# rustc's proc-macro based on whether calling it panics or not. i.e. it
	# uses std::panic::catch_unwind. This means that it aborts if panic=abort.
	# The latest version of proc-macro2 fixes this, provided rustc is >=
	# 1.57.0. So we can return to using panic=abort once we have updated to
	# 1.57.0 or later and updated proc-macro2.
	sed -i -e 's/panic=abort/panic=unwind/' "${CARGO_HOME}/config" || die
}
