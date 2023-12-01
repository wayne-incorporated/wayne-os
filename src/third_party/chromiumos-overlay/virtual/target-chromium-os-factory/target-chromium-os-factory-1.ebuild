# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of packages that are needed inside the Chromium OS factory
image."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE="no_factory_flow"

DEPEND="!chromeos-base/chromeos-factory"
RDEPEND="
	!no_factory_flow? (
		chromeos-base/factory
		${DEPEND}
	)
"
