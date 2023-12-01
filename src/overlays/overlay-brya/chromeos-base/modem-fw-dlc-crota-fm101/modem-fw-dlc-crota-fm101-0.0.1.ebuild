# Copyright 2022 The ChromiumOS Authors.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit dlc cros-binary

DESCRIPTION="DLC containing the modem firmware for crota_fm101."
HOMEPAGE="http://src.chromium.org"
MIRROR_PATH="gs://chromeos-localmirror/distfiles"
SRC_URI="
	${MIRROR_PATH}/cellular-firmware-fibocom-fm101-brya-19500.0000.00.01.01.52_A54.tar.xz
"

SLOT="0"
KEYWORDS="*"
LICENSE="BSD-Google" #TODO(b/203807072): Change once Fibocom provides a license

S="${WORKDIR}"

# For modem FWs, this value should never change, since there
# is no guarantee that the user will have enough space left to accommodate the
# increase in size.
# Each block is 4KB. We reserve enough space to fit:
# 2 Main FWs = ~110MB * 2
# Total = ~220 MB => 300MB to be safe
# 300MB/4KB = 75000
# Reserved space
DLC_PREALLOC_BLOCKS="75000"

# Installs the DLC during FSI.
DLC_FACTORY_INSTALL=true

#Preload on test images
DLC_PRELOAD=true

# Always update with the OS
DLC_CRITICAL_UPDATE=true

# Trusted dm-verity digest through LoadPin.
DLC_LOADPIN_VERITY_DIGEST=true

src_install() {
	insinto "$(dlc_add_path /fm101)"
	for f in cellular-firmware-fibocom-fm101-*; do
		doins -r "${f}"/*
	done
	dlc_src_install
}
