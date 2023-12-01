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

# The vast majority of packages should not be listed here!  You most likely
# want to update virtual/target-chromium-os-sdk instead.  Only list packages
# here that should not have build-time deps installed, e.g. Haskell leaf
# packages.
RDEPEND="
	dev-util/shellcheck
"
