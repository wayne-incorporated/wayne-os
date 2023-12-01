# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This is the DLC that packs the sr-bt models used in cras.

EAPI=7

inherit dlc

DESCRIPTION="Super resolution for Bluetooth microphone model dlc."
SRC_URI="gs://chromeos-localmirror/distfiles/chromeos-audio-sr-bt-${PV}.tar.xz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="dlc"
REQUIRED_USE="dlc"

# The size is about 2.1 * 3 ~ 6.3 MB
# Account for growth:
# 6.3 MB * 1.3 / 4KB block size = 2047.5 blocks
DLC_PREALLOC_BLOCKS="2048"
DLC_NAME="SR BT DLC"

DLC_PRELOAD=true

S="${WORKDIR}"

src_install() {
	insinto "$(dlc_add_path /)"
	doins "btwb.tflite"
	doins "btnb.tflite"
	doins "bt.tflite"
	dlc_src_install
}
