# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

DESCRIPTION="Android app to allow using UIAutomator remotely."
HOMEPAGE="https://github.com/lnishan/android-uiautomator-server"
# Use prebuilt binaries from python uiautomator lib.
SRC_URI="https://github.com/lnishan/uiautomator/archive/${PV}.zip -> ${P}.zip"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}/uiautomator-${PV}"

src_install() {
	insinto /usr/share/${PN}
	doins uiautomator/libs/app-uiautomator.apk
	doins uiautomator/libs/app-uiautomator-test.apk
}
