# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Install kexec upstart script"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"
IUSE=""

S=${WORKDIR}

DEPEND=""

RDEPEND="sys-apps/kexec-tools"

src_install() {
	insinto /etc/init
	doins "${FILESDIR}/kexec.conf"
}
