# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_RUST_REMOVE_DEV_DEPS=1
CROS_RUST_PREINSTALLED_REGISTRY_CRATE=1

inherit cros-rust

DESCRIPTION="Parser and serializer generator for protocol binary packets"
HOMEPAGE="https://crates.io/crates/pdl-compiler"

LICENSE="Apache-2.0"
SLOT="0/${PVR}"
KEYWORDS="*"

DEPEND="dev-rust/third-party-crates-src:="

RDEPEND="${DEPEND}"

src_compile() {
	ecargo_build
}

src_install() {
	dobin "$(cros-rust_get_build_dir)/pdlc"
}
