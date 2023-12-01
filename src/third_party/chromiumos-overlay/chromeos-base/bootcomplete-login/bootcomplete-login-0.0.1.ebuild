# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="Defines the boot-complete boot marker for ChromeOS
(login-prompt-visible signal emitted)"
HOMEPAGE="http://www.chromium.org/"
LICENSE="BSD-Google"
SLOT="0"

KEYWORDS="*"

RDEPEND="
	chromeos-base/chromeos-login
	!chromeos-base/bootcomplete-embedded
	"

S=${WORKDIR}

src_install() {
	insinto /etc/init
	doins "${FILESDIR}"/init/*.conf
}
