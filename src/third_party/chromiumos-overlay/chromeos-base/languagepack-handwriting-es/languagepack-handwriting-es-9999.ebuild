# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit dlc cros-workon

DESCRIPTION="Handwriting Spanish Language Pack for Chromium OS"

# "cros_workon info" expects these variables to be set, but we don't have a git
# repo, so use the standard empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

# Clients of Language Packs (Handwriting) need to update this path when new
# versions are available.
SRC_URI="gs://chromeos-localmirror/distfiles/languagepack-handwriting-es-20210730.tar.xz"


LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="dlc ondevice_handwriting"
REQUIRED_USE="dlc ondevice_handwriting"

# DLC variables.
# Allocate 4KB * 8750 = 35MB
DLC_PREALLOC_BLOCKS="8750"

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

	# Install handwriting models for Spanish.
	doins latin_indy.tflite latin_indy_conf.tflite latin_indy_seg.tflite
	newins es.compact.fst.local compact.fst.local
	newins qrnn.es.reco_20210729.fst_20210721.recospec.local qrnn.recospec.local

	# This command packages the files into a DLC.
	dlc_src_install
}
