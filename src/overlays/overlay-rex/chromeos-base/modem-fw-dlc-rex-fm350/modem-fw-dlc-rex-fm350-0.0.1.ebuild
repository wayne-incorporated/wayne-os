# Copyright 2023 The Chromium OS Authors. All rights reserved.
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit dlc cros-binary

DESCRIPTION="DLC containing the modem firmware for rex_fm350."
HOMEPAGE="http://src.chromium.org"
MIRROR_PATH="gs://chromeos-localmirror/distfiles"
SRC_URI="
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-81600.0000.00.29.19.16.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-FM350.C82.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-DEV_OTA_5001.0001.0000_Default_001.000.000.015.img.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-OP_OTA_000.037.img.tar.xz
	${MIRROR_PATH}/cellular-firmware-fibocom-fm350-OEM_OTA_6001.0000.001.img.tar.xz
	"

SLOT="0"
KEYWORDS="*"
LICENSE="BSD-Google" #TODO(b/203807072): Change once Fibocom provides a license

S="${WORKDIR}"

# For modem FWs, this value should never change, since there
# is no guarantee that the user will have enough space left to accommodate the
# increase in size.
# Each block is 4KB. We reserve enough space to fit:
# 3 Main FWs = ~45MB * 3
# Total = ~135 MB => 160MB to be safe
# 160MB/4KB = 40000
# Reserved space
DLC_PREALLOC_BLOCKS="40000"

# Installs the DLC during FSI.
DLC_FACTORY_INSTALL=true

#Preload on test images
DLC_PRELOAD=true

# Always update with the OS
DLC_CRITICAL_UPDATE=true

# Trusted dm-verity digest through LoadPin.
DLC_LOADPIN_VERITY_DIGEST=true

src_install() {
	insinto "$(dlc_add_path /fm350)"
	for f in cellular-firmware-fibocom-fm350-*; do
		doins -r "${f}"/*
	done
	dlc_src_install
}
