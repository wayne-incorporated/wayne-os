# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_RUST_PREINSTALLED_REGISTRY_CRATE=1
CROS_RUST_REMOVE_DEV_DEPS=1

inherit cros-rust

DESCRIPTION='C API for the "rustc-demangle" crate'
HOMEPAGE='https://crates.io/crates/rustc-demangle-capi'

LICENSE="|| ( MIT Apache-2.0 )"
SLOT="0/${PVR}"
KEYWORDS="*"

DEPEND="dev-rust/third-party-crates-src:="

src_compile() {
	# Force the build, since we don't want to install the sources for this.
	# Only the C-related artifacts are relevant.
	ecargo_build
}

src_install() {
	local build_dir="$(cros-rust_get_build_dir)"
	dolib.a "${build_dir}/librustc_demangle.a"
	doheader "${S}/include/rustc_demangle.h"
}
