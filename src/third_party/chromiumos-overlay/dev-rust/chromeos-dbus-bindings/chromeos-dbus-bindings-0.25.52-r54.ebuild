# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="16796b7547fa1fee9eeda1bd4d9353e059a94fbd"
CROS_WORKON_TREE="351fcfd810ba2cd5cca120e12de2259331ebde00"
CROS_RUST_SUBDIR="chromeos-dbus-bindings"

CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"

inherit cros-workon cros-rust

DESCRIPTION="Chrome OS D-Bus bindings generator for Rust."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/chromeos-dbus-bindings/"

LICENSE="BSD-Google"
SLOT="0/${PVR}"
KEYWORDS="*"

DEPEND="dev-rust/third-party-crates-src:="
RDEPEND="!chromeos-base/chromeos-dbus-bindings-rust
	${DEPEND}"

BDEPEND=">=dev-rust/dbus-codegen-0.10.0"
