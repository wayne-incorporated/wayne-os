# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="chromeos-base/chromeos-bsp-baseboard-fizz"
DEPEND="${RDEPEND}"

src_install() {
	doappid "{E6BF9F00-7982-4499-8C7D-FCB34A8AF43C}" "CHROMEBOX"
}
