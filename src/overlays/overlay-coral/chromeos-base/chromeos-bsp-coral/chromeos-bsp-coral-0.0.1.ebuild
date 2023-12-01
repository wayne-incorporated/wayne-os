# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid
inherit cros-unibuild

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0" # TODO (b/185804190): convert this to cros-workon
KEYWORDS="-* amd64 x86"
IUSE="coral-kernelnext modemfwd"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-coral
	modemfwd? ( chromeos-base/modemfwd-helpers )
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use coral-kernelnext; then
		doappid "{79A287C6-9BC1-11EB-9537-63CE10F4C525}" "CHROMEBOOK"
	else
		doappid "{5A3AB642-2A67-470A-8F37-37E737A53CFC}" "CHROMEBOOK"
	fi

	unibuild_install_files audio-files
	unibuild_install_files thermal-files

	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/common/powerd/*
}
