# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Google text suggestions library for Chrome OS"
HOMEPAGE="https://www.chromium.org/chromium-os"

LICENSE="BSD-Google"
SLOT="0"

DIST_URL="gs://chromeos-localmirror/distfiles"
SRC_URI="
	amd64? ( ${DIST_URL}/libsuggest-amd64-${PV}.tar.gz )
	arm? ( ${DIST_URL}/libsuggest-arm-${PV}.tar.gz )
	arm64? ( ${DIST_URL}/libsuggest-arm64-${PV}.tar.gz )
	"

KEYWORDS="*"

IUSE="ondevice_text_suggestions"

S="${WORKDIR}"

LIB_PATH="libsuggest-${ARCH}"

src_install() {
	# Always install the header and proto files.
	insinto /usr/include/chromeos/libsuggest/
	doins "${LIB_PATH}/text_suggester_interface.h"
	insinto /usr/include/chromeos/libsuggest/proto/
	doins "${LIB_PATH}/text_suggester_interface.proto"

	if use ondevice_text_suggestions; then
		insinto /opt/google/chrome/ml_models/suggest/
		# Install shared lib
		insopts -m0755
		doins "${LIB_PATH}/libsuggest.so"
		insopts -m0644
		# Install the model artifacts.
		doins "${LIB_PATH}/nwp.uint8.mmap.tflite"
		doins "${LIB_PATH}/nwp.csym"
		doins "${LIB_PATH}/nwp.20220920.uint8.mmap.tflite"
		doins "${LIB_PATH}/nwp.20220920.csym"
	fi
}
