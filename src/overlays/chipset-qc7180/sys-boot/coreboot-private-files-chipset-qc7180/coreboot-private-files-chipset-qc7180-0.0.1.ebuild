# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Coreboot private files for SC7180 chipset (public)"
SLOT="0"
KEYWORDS="*"
LICENSE="BSD-Google"

DEPEND="
	sys-boot/sc7180-qc_blobs
	"
RDEPEND="${DEPEND}"
