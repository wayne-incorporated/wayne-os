# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Google grammar check library for Chrome OS"
HOMEPAGE="https://www.chromium.org/chromium-os"

LICENSE="BSD-Google"
SLOT="0"

DIST_URL="gs://chromeos-localmirror/distfiles"
SRC_URI="
	amd64? ( ${DIST_URL}/libgrammar-amd64-${PV}.tar.gz )
	arm? ( ${DIST_URL}/libgrammar-arm-${PV}.tar.gz )
	arm64? ( ${DIST_URL}/libgrammar-arm64-${PV}.tar.gz )
	"

KEYWORDS="*"

IUSE="ondevice_grammar"

S="${WORKDIR}"

LIB_PATH="libgrammar-${ARCH}"
MODEL_PATH="libgrammar-${ARCH}/sentence_explorer_cpu"

src_install() {
	# Always install the header and proto files.
	insinto /usr/include/chromeos/libgrammar/
	doins "${LIB_PATH}/grammar_interface.h"
	insinto /usr/include/chromeos/libgrammar/proto/
	doins "${LIB_PATH}/grammar_interface.proto"

	if use ondevice_grammar; then
		insinto /opt/google/chrome/ml_models/grammar/
		# Install the shared library.
		insopts -m0755
		doins "${LIB_PATH}/libgrammar.so"
		insopts -m0644
		# Install the model files.
		doins "${MODEL_PATH}/translation_model.pb"
		doins "${MODEL_PATH}/model.pb"
		doins "${MODEL_PATH}/decoder_init_0.tflite"
		doins "${MODEL_PATH}/decoder_step_0.tflite"
		doins "${MODEL_PATH}/encoder_0.tflite"
		doins "${MODEL_PATH}/wpm.model"
		doins "${MODEL_PATH}/wpm.vocab"
	fi
}
