# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon

DESCRIPTION="List of packages that are needed inside the SDK, but after we've
built all the toolchain packages that we install separately via binpkgs.  This
avoids circular dependencies when bootstrapping."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="~*"
IUSE=""

# The vast majority of packages should not be listed here!  You most likely
# want to update virtual/target-chromium-os-sdk instead.  Only list packages
# here that need the cross-compiler toolchains installed first.
RDEPEND="
	dev-lang/rust
	dev-embedded/coreboot-sdk
	dev-embedded/ti50-sdk
"

# Needed for hps-firmware.
RDEPEND="${RDEPEND}
	dev-embedded/hps-sdk
"
