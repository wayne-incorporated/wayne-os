# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Chrome OS BSP virtual test package.
This virutal is pulled by chromeos-base/chromeos-test-root."
HOMEPAGE="http://src.chromium.org"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND="chromeos-base/chromeos-test-testauthkeys"
RDEPEND="${DEPEND}
"
