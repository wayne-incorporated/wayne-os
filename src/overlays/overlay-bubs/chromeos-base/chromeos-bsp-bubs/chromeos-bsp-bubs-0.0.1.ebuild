# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
EAPI=6

inherit appid

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE=""
S="${WORKDIR}"

RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-trogdor
"
DEPEND="${RDEPEND}"

src_install() {
	doappid "{2AB7AC10-90E7-4E03-9A54-359EE2CC08BB}" "REFERENCE"
}
