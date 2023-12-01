# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

LICENSE="metapackage"

DESCRIPTION="coreboot private files virtual package"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	sys-boot/coreboot-private-files-chipset-sc7280
	"
DEPEND="${RDEPEND}"
