# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid cros-unibuild

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="aurora aurora-borealis"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use aurora-borealis; then
		doappid "{567CE7C6-688F-897C-6C1A-0F4C15CC24E7}" "CHROMEBOOK"
	elif use aurora; then
		doappid "{DD70ECA8-C39D-2BAA-055C-9094D3A78BE1}" "CHROMEBOOK"
	fi
}
