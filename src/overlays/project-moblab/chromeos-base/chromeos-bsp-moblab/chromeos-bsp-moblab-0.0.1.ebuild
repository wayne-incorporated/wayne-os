# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit user

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies or portage actions"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	app-emulation/docker
	net-firewall/iptables
"

# Chromium OS Autotest Server and Devserver Deps.
RDEPEND="${RDEPEND}
	sys-apps/moblab
	sys-apps/satlab
"

DEPEND=""

S=${WORKDIR}

pkg_preinst() {
	enewgroup moblab
	enewuser moblab
	usermod -a -G docker moblab
}

src_install() {
	insinto /etc/init
	doins "${FILESDIR}/cgroups.override"
}
