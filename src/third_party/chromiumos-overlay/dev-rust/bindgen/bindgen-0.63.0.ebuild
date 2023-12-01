# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_RUST_CRATE_NAME=bindgen-cli
CROS_RUST_PREINSTALLED_REGISTRY_CRATE=1

inherit cros-rust

DESCRIPTION='Automatically generates Rust FFI bindings to C and C++ libraries.'
HOMEPAGE='https://rust-lang.github.io/rust-bindgen/'

LICENSE="BSD"
SLOT="0/${PVR}"
KEYWORDS="*"

DEPEND="dev-rust/third-party-crates-src:="
RDEPEND="${DEPEND}"

src_compile() {
	ecargo_build
}

src_install() {
	dobin "$(cros-rust_get_build_dir)/bindgen"
}
