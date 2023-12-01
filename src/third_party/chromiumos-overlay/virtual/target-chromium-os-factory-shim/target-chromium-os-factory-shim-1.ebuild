# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of packages that are needed inside the Chromium OS factory
shim image."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE="no_factory_flow"

RDEPEND="
	!no_factory_flow? ( chromeos-base/chromeos-installshim )
"
