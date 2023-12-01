# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit cros-camera dlc unpacker

DESCRIPTION="Package for document scanner library as a DLC"
SRC_URI="$(cros-camera_generate_document_scanning_package_SRC_URI ${PV})"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

# The size of the Document Scanner library is about 8.5 MB. Therefore,
# considering the future growth, we should reserve 8.5 * 130% ~= 12 MB.
DLC_PREALLOC_BLOCKS="$((12 * 256))"

DLC_PRELOAD=true

src_install() {
	# Since document_scanner.h is required for all builds, it is installed in
	# cros-camera-libfs package.

	exeinto "$(dlc_add_path /)"

	doexe "libdocumentscanner.so"
	dlc_src_install
}
