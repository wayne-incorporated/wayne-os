# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

# This ebuild is used to install the Xerox PPD license into Chrome OS. PPDs are
# served separately from the operating system through a static content server,
# but in order for their associated licenses to appear in the os-credits page a
# license must be generated from an ebuild.

EAPI=6

DESCRIPTION="Licenses for Xerox PPD files"
HOMEPAGE="http://dev.chromium.org"


LICENSE="LICENSE.xerox-ppds"
SLOT="0"
KEYWORDS="*"
IUSE="internal"
REQUIRED_USE="internal"
