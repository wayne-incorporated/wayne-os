# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

inherit user

DESCRIPTION="Ebuild which properly configures the Chrome OS enviornment for android tools."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
	chromeos-base/chromeos-base
"

RDEPEND="${DEPEND}
	dev-util/android-tools
"

S=${WORKDIR}

pkg_preinst() {
	enewgroup adb
	enewuser adb
}

src_install() {
	insinto /etc/init
	doins "${FILESDIR}"/*.conf

	insinto /etc/sudoers.d
	echo "adb ALL = NOPASSWD: /usr/bin/adb" > adb-adb
	insopts -m600
	doins adb-adb
}
