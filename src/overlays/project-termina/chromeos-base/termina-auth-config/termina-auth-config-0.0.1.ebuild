# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit pam

DESCRIPTION="Termina-specific configuration files for pambase"
HOMEPAGE="http://www.chromium.org"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND="!<=sys-apps/shadow-4.1.2.2-r6
	>=sys-auth/pambase-20090620.1-r7"
DEPEND="${RDEPEND}"

S="${WORKDIR}"

src_install() {
	# A custom pam config is needed for passwordless login for chronos/root.
	insinto /etc/pam.d
	doins "${FILESDIR}"/termina-auth

	newpamd "${FILESDIR}"/include-termina-auth login
	pamd_mimic system-local-login login auth account password session
}
