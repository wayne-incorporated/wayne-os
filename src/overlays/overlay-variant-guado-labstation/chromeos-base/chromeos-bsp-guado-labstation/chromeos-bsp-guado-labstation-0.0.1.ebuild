# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=4

inherit appid

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
S="${WORKDIR}"

src_install() {
	doappid "{41D57E57-2150-BB76-2730-EC8AFD1D835D}" "CHROMEBOX"
	insinto /etc/init
	doins "${FILESDIR}"/init/*.conf
}
