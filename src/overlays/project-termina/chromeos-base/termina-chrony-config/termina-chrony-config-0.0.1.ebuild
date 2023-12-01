# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="Install configuration and scripts for chrony"
HOMEPAGE="http://www.chromium.org/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	net-misc/chrony
"

S=${WORKDIR}

src_install() {
	insinto /etc/maitred/
	doins "${FILESDIR}"/00-chrony.textproto

	insinto /etc/chrony/
	doins "${FILESDIR}"/termina.conf
}
