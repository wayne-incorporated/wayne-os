# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="coreboot private files virtual package"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	sys-boot/coreboot-private-files-chipset-qc7180
	"
DEPEND="${RDEPEND}"
