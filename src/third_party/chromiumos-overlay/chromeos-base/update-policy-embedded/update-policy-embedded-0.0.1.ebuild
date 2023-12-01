# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="Install the update_engine policy for embedded boards"
HOMEPAGE="http://www.chromium.org/"
LICENSE="BSD-Google"
SLOT="0"

KEYWORDS="*"

RDEPEND="
	!<chromeos-base/update_engine-0.0.2
	!chromeos-base/update-policy-chromeos
"

S=${WORKDIR}

src_install() {
	insinto /etc
	doins "${FILESDIR}"/update_manager.conf
}
