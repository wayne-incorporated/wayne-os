# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v3

EAPI=7

inherit dlc

DESCRIPTION='ScreenAI is a binary to provide AI based models to improve
assistive technologies. The binary is written in C++ and is currently used by
ReadAnything and PdfOcr services on Chrome OS.'
HOMEPAGE=""

if [[ ${PV} != 9999 ]]; then
	SRC_URI="
		arm? ( gs://chromeos-localmirror/distfiles/${PN}-arm32-${PV}.tar.xz -> ${PN}-arm32-${PV}.tar.xz )
		arm64? ( gs://chromeos-localmirror/distfiles/${PN}-arm64-${PV}.tar.xz -> ${PN}-arm64-${PV}.tar.xz )
		amd64? ( gs://chromeos-localmirror/distfiles/${PN}-amd64-${PV}.tar.xz -> ${PN}-amd64-${PV}.tar.xz )
	"
fi

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="dlc"
REQUIRED_USE="dlc"

# DLC variables.
# 4KB * 5773 = ~23 MB
DLC_PREALLOC_BLOCKS="5773"
DLC_PRELOAD=false
DLC_SCALED=true

S="${WORKDIR}"

src_install() {
	# Install binary.
	insinto "$(dlc_add_path /)"
	doins libchromescreenai.so

	# Install Main Content Extraction model files.
	doins screen2x_config.pbtxt screen2x_model.tflite

	# Install OCR model files.
	# We need to put OCR model files in the same directory
	# structure as their Google3 locations. This requierment will be removed
	# after we update the file handling so that the files would be loaded in
	# Chrome and passed to the binary.
	doins \
		taser_tflite_gocrlatinconvnext320_mbv2_scriptid_aksara_layout_gro_mobile_engine_ti.binarypb
	doins \
		taser_tflite_gocrlatinconvnext320_mbv2_scriptid_aksara_layout_gro_mobile_recognizer.binarypb
	insinto "$(dlc_add_path /aksara)"
	doins \
		aksara/aksara_page_layout_analysis_ti_rpn_gro.binarypb
	insinto "$(dlc_add_path /gocr)"
	insinto "$(dlc_add_path /gocr/gocr_models)"
	insinto \
		"$(dlc_add_path /gocr/gocr_models/line_recognition_mobile_convnext320)"
	doins \
		gocr/gocr_models/line_recognition_mobile_convnext320/tflite_langid.tflite
	doins \
		gocr/gocr_models/line_recognition_mobile_convnext320/Latn_ctc_cpu.binarypb
	insinto \
		"$(dlc_add_path /gocr/gocr_models/line_recognition_mobile_convnext320/Latn_ctc)"
	insinto \
		"$(dlc_add_path /gocr/gocr_models/line_recognition_mobile_convnext320/Latn_ctc/optical)"
	doins \
		gocr/gocr_models/line_recognition_mobile_convnext320/Latn_ctc/optical/model.fb
    insinto \
		"$(dlc_add_path /gocr/gocr_models/line_recognition_mobile_convnext320/Latn_ctc/optical/assets.extra)"
	doins \
		gocr/gocr_models/line_recognition_mobile_convnext320/Latn_ctc/optical/assets.extra/LabelMap.pb
	insinto "$(dlc_add_path /layout)"
	insinto "$(dlc_add_path /gocr/layout/line_splitting_custom_ops)"
	doins gocr/layout/line_splitting_custom_ops/model.tflite
	insinto "$(dlc_add_path /gocr/layout/cluster_sort_custom_ops)"
	doins gocr/layout/cluster_sort_custom_ops/model.tflite
	insinto "$(dlc_add_path /taser)"
	doins taser/rpn_text_detection_tflite_mobile_mbv2.binarypb
	doins taser/taser_script_identification_tflite_mobile.binarypb
	insinto "$(dlc_add_path /taser/detector)"
	doins \
		taser/detector/region_proposal_text_detector_tflite_vertical_mbv2_v1.bincfg
	doins \
		taser/detector/rpn_text_detector_mobile_space_to_depth_quantized_mbv2_v1.tflite
	insinto "$(dlc_add_path /taser/segmenter)"
	doins taser/segmenter/tflite_script_detector_0.3.bincfg
	doins taser/segmenter/tflite_script_detector_0.3.conv_model
	doins taser/segmenter/tflite_script_detector_0.3.lstm_model

	dlc_src_install
}
