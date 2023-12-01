# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Coreboot private files for Trogdor baseboard (public)"
SLOT="0"
KEYWORDS="*"
LICENSE="BSD-Google"

DEPEND="
	sys-boot/coreboot-private-files-chipset-qc7180
	sys-firmware/parade-ps8751a3-firmware
	sys-firmware/parade-ps8755a2-firmware
	sys-firmware/parade-ps8805a2-firmware
	sys-firmware/parade-ps8805a3-firmware
	"
RDEPEND="${DEPEND}"
