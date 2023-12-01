# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="4"

DESCRIPTION="Install the upstart jobs that configure the firewall."
HOMEPAGE="http://www.chromium.org/"
LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}

RDEPEND="
	chromeos-base/chromeos-init
	net-firewall/iptables[ipv6]
"

src_install() {
	insinto /etc/init
	doins "${FILESDIR}"/*.conf
}
