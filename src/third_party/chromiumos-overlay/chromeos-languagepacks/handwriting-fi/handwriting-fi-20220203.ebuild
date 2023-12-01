# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit dlc

DESCRIPTION="Handwriting fi Language Pack for Chromium OS"
HOMEPAGE="https://www.chromium.org/chromium-os"

# Clients of Language Packs (Handwriting) need to update this path when new
# versions are available.
SRC_URI="gs://chromeos-localmirror/distfiles/languagepack-handwriting-fi-${PV}.tar.xz"


LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

IUSE="dlc ondevice_handwriting"
REQUIRED_USE="dlc ondevice_handwriting"

# DLC variables.
# Allocate 4KB * 8750 = 35MB
DLC_PREALLOC_BLOCKS="8750"

# Enable scaled design.
DLC_SCALED=true

S="${WORKDIR}"
src_unpack() {
	local archive="${SRC_URI##*/}"
	unpack ${archive}
}

src_install() {
	# This DLC is enabled only if ondevice handwriting is enabled.
	if ! use ondevice_handwriting; then
		return
	fi

	# Setup DLC paths. We don't need any subdirectory inside the DLC path.
	into "$(dlc_add_path /)"
	insinto "$(dlc_add_path /)"
	exeinto "$(dlc_add_path /)"

	# Install handwriting models for fi.
	doins compact.fst.local latin_indy.tflite latin_indy_conf.tflite
	doins latin_indy_seg.tflite qrnn.recospec.local

	# This command packages the files into a DLC.
	dlc_src_install
}
