# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Chrome OS BSP virtual package"
HOMEPAGE="http://src.chromium.org"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"

RDEPEND="chromeos-base/chromeos-bsp-mobbase
	chromeos-base/chromeos-bsp-satlab
	chromeos-base/chromeos-bsp-fizz-satlab"
