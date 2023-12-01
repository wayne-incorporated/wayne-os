# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit dlc cros-binary

DESCRIPTION="DLC containing the modem firmware for primus_l850."
HOMEPAGE="http://src.chromium.org"
MIRROR_PATH="gs://chromeos-localmirror/distfiles"
SRC_URI="
	${MIRROR_PATH}/cellular-firmware-fibocom-l850-18500.5001.00.05.27.12_Secureboot.tar.xz
"

SLOT="0"
KEYWORDS="*"
LICENSE="BSD-Google" #TODO(b/203807072): Change once Fibocom provides a license

S="${WORKDIR}"

# For modem FWs, this value should never change, since there
# is no guarantee that the user will have enough space left to accommodate the
# increase in size.
# Each block is 4KB. We reserve enough space to fit:
# 2 Main FWs = ~11.5MB * 2
# 1 OEM FW = 125KB
# 1 OEM carrier pack = 2MB
# Total = ~26 MB => 40MB to be safe
# 40MB/4KB = 10000
# Reserved space
DLC_PREALLOC_BLOCKS="10000"

# Installs the DLC during FSI.
DLC_FACTORY_INSTALL=true

#Preload on test images
DLC_PRELOAD=true

# Always update with the OS
DLC_CRITICAL_UPDATE=true

# Trusted dm-verity digest through LoadPin.
DLC_LOADPIN_VERITY_DIGEST=true

src_install() {
	insinto "$(dlc_add_path /l850)"
	for f in cellular-firmware-fibocom-l850-*; do
		doins -r "${f}"/*
	done
	dlc_src_install
}
