# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0" # TODO (b/185804190): convert this to cros-workon
KEYWORDS="-* amd64 x86"
IUSE="unibuild snappy-kernelnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/chromeos-bsp-baseboard-reef
"
DEPEND="${RDEPEND}"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use snappy-kernelnext; then
		doappid "{6C77510C-923F-11EB-B7C0-4323D910C0BE}" "CHROMEBOOK"
	else
		doappid "{F8834CDD-B93C-4C2A-BEB9-5432EA99430D}" "CHROMEBOOK"
	fi

	exeinto /usr/share/cros
	doexe "${FILESDIR}"/oemdata.sh
}
