# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Virtual package installing the boot-complete boot marker that
represents the system being operationnal and ready to use.
Boards should override it to define their own boot-complete."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE="cros_embedded"

RDEPEND="
	|| (
		!cros_embedded? ( chromeos-base/bootcomplete-login )
		chromeos-base/bootcomplete-embedded
	)
"

DEPEND="${RDEPEND}"
