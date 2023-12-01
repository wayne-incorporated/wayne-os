# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Coreboot private files for SC7280 chipset (public)"
SLOT="0"
KEYWORDS="*"
LICENSE="BSD-Google"

DEPEND="
	sys-boot/sc7280-qc_blobs
	"
RDEPEND="${DEPEND}"
