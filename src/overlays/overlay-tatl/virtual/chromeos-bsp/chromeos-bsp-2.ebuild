# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Chrome OS BSP virtual package"
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	chromeos-base/chromeos-bsp-tatl
	chromeos-base/chromeos-bsp-termina
"
