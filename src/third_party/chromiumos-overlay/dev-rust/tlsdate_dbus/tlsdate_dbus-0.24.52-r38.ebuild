# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="db811efad1d655e5aad763d0871aa4e97fcbfcfc"
CROS_WORKON_TREE="74a06cf18979221e62556d5476c88f1cca43fa94"
CROS_WORKON_PROJECT="chromiumos/third_party/tlsdate"
CROS_WORKON_EGIT_BRANCH="master"
CROS_WORKON_LOCALNAME="tlsdate"

inherit cros-workon cros-rust

CROS_RUST_SUBDIR=""

DESCRIPTION="Rust D-Bus bindings for tlsdate."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/tlsdate/+/master/"

LICENSE="BSD-Google"
SLOT="0/${PVR}"
KEYWORDS="*"

DEPEND="
	dev-rust/third-party-crates-src:=
	dev-rust/chromeos-dbus-bindings:=
	sys-apps/dbus:=
"
# (crbug.com/1182669): build-time only deps need to be in RDEPEND so they are pulled in when
# installing binpkgs since the full source tree is required to use the crate.
RDEPEND="${DEPEND}"
