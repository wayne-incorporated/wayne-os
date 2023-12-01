# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit user

DESCRIPTION="Ebuild to support running docker on chromeos"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

inherit tmpfiles

# note this does not rdepend on app-containers/docker to allow for flexibility
# this package needs to be installed in the base image to work but docker packages
# could be installed on test/dev image to minimize space used in the rootfs
RDEPEND="
	net-firewall/iptables
"

DEPEND=""

S=${WORKDIR}

src_install() {
	insinto /etc/init
	doins "${FILESDIR}"/init/*.conf
	doins "${FILESDIR}/cgroups.override"

	insinto /usr/share/cros/startup/symlink_exceptions/
	doins "${FILESDIR}"/docker-symlink-exceptions.txt
}
