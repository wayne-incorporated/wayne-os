# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This ebuild is used to install the Konica Minolta PPD license into Chrome OS. PPDs are
# served separately from the operating system through a static content server,
# but in order for their associated licenses to appear in the os-credits page a
# license must be generated from an ebuild.

EAPI=6

DESCRIPTION="Licenses for Konica Minolta PPD files"
HOMEPAGE="http://dev.chromium.org"


LICENSE="LICENSE.konica-minolta-ppds"
SLOT="0"
KEYWORDS="*"
IUSE="internal"
REQUIRED_USE="internal"
