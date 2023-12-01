# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit user

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies or portage actions"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND=""
DEPEND=""

S=${WORKDIR}

pkg_preinst() {
	usermod -a -G docker $USER
}

src_install() {
	insinto /etc/init
	doins "${FILESDIR}/"*.conf
	doins "${FILESDIR}/"cgroups.override
}
