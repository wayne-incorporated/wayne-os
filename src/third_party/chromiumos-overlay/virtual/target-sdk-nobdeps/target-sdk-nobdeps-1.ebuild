# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of packages that are needed inside the SDK, but where we only
want to install a binpkg.  We never want to install build-time deps or recompile
from source unless the user explicitly requests it."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="virtual/target-chromium-os-sdk-nobdeps"
DEPEND="${RDEPEND}"
