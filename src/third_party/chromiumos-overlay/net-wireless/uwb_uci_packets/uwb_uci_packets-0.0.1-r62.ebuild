# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_COMMIT=("8164aa4ce27568d1f05bb1d4fab361b130e7e125" "753f19061fb32a0689352ecf9ee1e00242ce7da0")
CROS_WORKON_TREE=("c92161192e85aafc29873647d09c8d13d9deb0e0" "c92161192e85aafc29873647d09c8d13d9deb0e0")
CROS_WORKON_PROJECT=(
	"aosp/platform/external/uwb"
	"aosp/platform/external/uwb"
)
CROS_WORKON_LOCALNAME=(
	"../aosp/external/uwb/local"
	"../aosp/external/uwb/upstream"
)
CROS_WORKON_DESTDIR=(
	"${S}"
	"${S}"
)
CROS_WORKON_SUBTREE=("src/rust/uwb_uci_packets" "src/rust/uwb_uci_packets")
CROS_WORKON_EGIT_BRANCH=("main" "upstream/master")
CROS_WORKON_OPTIONAL_CHECKOUT=(
	"use !uwb_upstream"
	"use uwb_upstream"
)
CROS_RUST_SUBDIR="src/rust/uwb_uci_packets"

inherit cros-workon cros-rust

DESCRIPTION="The UWB UCI packets library"
HOMEPAGE="https://chromium.googlesource.com/aosp/platform/external/uwb/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"
IUSE="uwb_upstream"

BDEPEND="
	dev-util/pdl-compiler
"
DEPEND="
	dev-rust/third-party-crates-src:=
"
RDEPEND="${DEPEND}"
