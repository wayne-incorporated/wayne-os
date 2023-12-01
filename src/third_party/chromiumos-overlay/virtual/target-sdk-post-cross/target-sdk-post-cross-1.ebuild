# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of packages that are needed inside the SDK, but after we've
built all the toolchain packages that we install separately via binpkgs.  This
avoids circular dependencies when bootstrapping."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="virtual/target-chromium-os-sdk-post-cross"
DEPEND="${RDEPEND}"
