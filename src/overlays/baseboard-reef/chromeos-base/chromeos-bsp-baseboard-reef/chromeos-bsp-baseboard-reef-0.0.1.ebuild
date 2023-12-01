# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE=""
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-disk-firmware-baseboard-reef
"
DEPEND="${RDEPEND}"

src_install() {
	# Install board-specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/board_specific/*

	# Install model-specific bluetooth config files
	insinto "/etc/bluetooth"
	doins -r "${FILESDIR}"/bluetooth/*
}
