# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Chrome OS BSP virtual test package"
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

DEPEND="chromeos-base/chromeos-test-testauthkeys"
RDEPEND="${DEPEND}
"
