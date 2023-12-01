# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This lives separately from the main minijail ebuild since we don't have Rust
# available in the SDK builder.
# TODO: Consider moving back into main ebuild once crbug.com/1046088 is
# resolved.

EAPI=7

inherit cros-constants

CROS_RUST_SUBDIR="rust/minijail-sys"

CROS_WORKON_LOCALNAME="../platform/minijail"
CROS_WORKON_PROJECT="chromiumos/platform/minijail"
CROS_WORKON_EGIT_BRANCH="main"

inherit cros-workon cros-rust

DESCRIPTION="rust bindings for minijail"
HOMEPAGE="https://google.github.io/minijail"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="test"

# ebuilds that install executables and depend on minijail-sys need to RDEPEND on
# chromeos-base/minijail and sys-libs/libcap
DEPEND="
	dev-rust/third-party-crates-src:=
	chromeos-base/minijail:=
	sys-libs/libcap:=
"
# (crbug.com/1182669): build-time only deps need to be in RDEPEND so they are pulled in when
# installing binpkgs since the full source tree is required to use the crate.
RDEPEND="${DEPEND}"
