# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Firmware updater for Intel's AX211 WiFi chipset."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND=""

S=${WORKDIR}

src_install() {
	exeinto /usr/share/cros/init
	doexe "${FILESDIR}/ax211-updater.sh"
}
