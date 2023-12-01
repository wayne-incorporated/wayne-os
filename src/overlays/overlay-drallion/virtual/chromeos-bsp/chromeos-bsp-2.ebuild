# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Chrome OS BSP virtual package"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="-* amd64 x86"

RDEPEND="
	chromeos-base/chromeos-bsp-drallion
	chromeos-base/chromeos-bsp-wilco
"
