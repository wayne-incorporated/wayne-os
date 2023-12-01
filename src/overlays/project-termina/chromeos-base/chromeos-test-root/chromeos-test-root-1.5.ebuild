# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Install packages that must live in the rootfs in test images."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	app-benchmarks/pjdfstest
	chromeos-base/chromeos-test-testauthkeys
	virtual/chromeos-bsp-test-root
"
