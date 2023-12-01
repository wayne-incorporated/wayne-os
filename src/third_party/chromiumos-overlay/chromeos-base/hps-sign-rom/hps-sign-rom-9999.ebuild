# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_PROJECT="chromiumos/platform/hps-firmware"
CROS_WORKON_LOCALNAME="platform/hps-firmware2"
CROS_RUST_SUBDIR="rust/sign-rom"

inherit cros-workon cros-rust

DESCRIPTION="Tool to sign HPS firmware"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/hps-firmware"

LICENSE="BSD-Google"
KEYWORDS="~*"

DEPEND="
	dev-rust/third-party-crates-src:=
	dev-embedded/libftdi:=
	virtual/libusb:1
"

# /usr/bin/hps-sign-rom moved from hps-firmware-tools to here
RDEPEND="
	!<chromeos-base/hps-firmware-tools-0.0.1-r141
"

src_prepare() {
	# config.toml is intended for use when running `cargo` directly but would
	# mess with the ebuild if we didn't delete it.
	rm -f ../.cargo/config.toml

	cros-rust_src_prepare
}

src_test() {
	# All Rust unit tests (including the ones for sign-rom)
	# are executed by src_test in the hps-firmware package.
	# Nothing else to do here.
	:
}

src_install() {
	newbin "$(cros-rust_get_build_dir)/sign-rom" hps-sign-rom
}
