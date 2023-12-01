# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="Define the boot-complete boot marker for embedded systems
(boot-services up and running)"
HOMEPAGE="http://www.chromium.org/"
LICENSE="BSD-Google"
SLOT="0"

KEYWORDS="*"

RDEPEND="
	!chromeos-base/bootcomplete-login
"

S=${WORKDIR}

src_install() {
	insinto /etc/init
	doins "${FILESDIR}"/init/*.conf
}
