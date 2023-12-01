# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies or portage actions"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

S=${WORKDIR}

src_install() {
	insinto /etc
	doins "${FILESDIR}"/arc_host.conf

	dosbin "${FILESDIR}"/cros-mount-external

	insinto /etc/profile.d
	doins "${FILESDIR}"/PS1-termina.sh

	insinto /etc/maitred
	doins "${FILESDIR}/10-mount-vm-tools.textproto"
	doins "${FILESDIR}/11-mount-external.textproto"
	doins "${FILESDIR}/50-mount-fonts.textproto"
}
