# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="cc0fdde56c223901cbb9c689f8e853d36cecb4dc"
CROS_WORKON_TREE=("a4c31e84f65a207a372212467baa664fe2b07038" "8aad1415bc8edb5dd4fbbff205b67e7b6453d708")
inherit cros-constants

CROS_RUST_SUBDIR="rust/vboot_reference-sys"

CROS_WORKON_PROJECT="chromiumos/platform/vboot_reference"
CROS_WORKON_LOCALNAME="../platform/vboot_reference"
CROS_WORKON_SUBTREE="host/include rust/vboot_reference-sys"

inherit cros-workon cros-rust

DESCRIPTION="Chrome OS verified boot tools Rust bindings"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/vboot_reference/+/HEAD/rust"

LICENSE="BSD-Google"
KEYWORDS="*"

# ebuilds that install executables and depend on vboot_reference-sys need to
# RDEPEND on chromeos-base/vboot_reference
DEPEND="
	dev-rust/third-party-crates-src:=
	chromeos-base/vboot_reference:=
	virtual/bindgen:=
"
# (crbug.com/1182669): build-time only deps need to be in RDEPEND so they are pulled in when
# installing binpkgs since the full source tree is required to use the crate.
RDEPEND="${DEPEND}"
