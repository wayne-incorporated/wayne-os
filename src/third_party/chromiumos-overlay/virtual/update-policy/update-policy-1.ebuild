# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Virtual package installing the update engine's policy manager
configuration. Boards can override it to install their own configuration."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE="cros_embedded"

RDEPEND="
	|| (
		!cros_embedded? ( chromeos-base/update-policy-chromeos )
		chromeos-base/update-policy-embedded
	)
"
DEPEND="${RDEPEND}"
