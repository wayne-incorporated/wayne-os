# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_RUST_REMOVE_DEV_DEPS=1

inherit cros-rust

DESCRIPTION="A VK-GL-CTS/dEQP wrapper program to parallelize it across CPUs and report results against a baseline."
HOMEPAGE="https://gitlab.freedesktop.org/anholt/deqp-runner"
SRC_URI="https://crates.io/api/v1/crates/${PN}/${PV}/download -> ${P}.crate"

LICENSE="MIT"
SLOT="0/${PR}"
KEYWORDS="*"

DEPEND="dev-rust/third-party-crates-src:="

src_configure() {
	append-lfs-flags
	cros-rust_src_configure
}

src_compile() {
	ecargo_build
}

src_install() {
	local build_dir="$(cros-rust_get_build_dir)"

	dobin "${build_dir}/deqp-runner"
}
