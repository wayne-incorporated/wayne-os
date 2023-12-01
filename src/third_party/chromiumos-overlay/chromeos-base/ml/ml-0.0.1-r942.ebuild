# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "3d73674b3bfdc407eabb875b7b4c71dba3130f2e" "c44d427133b6713fe883542acded6563ecb2adb7" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "fa0665bfd3f2b980857d473daf71e5c489e2b28e")
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
# TODO(amoylan): Set CROS_WORKON_OUTOFTREE_BUILD=1 after crbug.com/833675.
CROS_WORKON_DESTDIR="${S}/platform2"
CROS_WORKON_SUBTREE="common-mk ml ml_benchmark .gn ml_core"

PLATFORM_SUBDIR="ml"

inherit cros-workon platform user

DESCRIPTION="Machine learning service for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/main/ml"

# Clients of the ML service should place the URIs of their model files into
# MODELS_TO_INSTALL if they are installed into rootfs (built-in models), or
# DOWNLOADABLE_MODELS if they are downloaded via component updater (downloadable
# models).
MODELS_TO_INSTALL=(
	"gs://chromeos-localmirror/distfiles/mlservice-model-test_add-20180914.tflite"
	"gs://chromeos-localmirror/distfiles/mlservice-model-search_ranker-20190923.tflite"
	"gs://chromeos-localmirror/distfiles/mlservice-model-smart_dim-20190521-v3.tflite"
	"gs://chromeos-localmirror/distfiles/mlservice-model-adaptive_charging-20211105.tflite"
	"gs://chromeos-localmirror/distfiles/mlservice-model-poncho_palm_rejection-test_quantized_20230213.tflite"
	"gs://chromeos-localmirror/distfiles/mlservice-model-adaptive_charging-20230314.tflite"
)

DOWNLOADABLE_MODELS=(
	"gs://chromeos-localmirror/distfiles/mlservice-model-smart_dim-20200206-downloadable.tflite"
	"gs://chromeos-localmirror/distfiles/mlservice-model-smart_dim-20210201-downloadable.tflite"
)

# Clients that want ml-service to do the feature preprocessing should place the
# URIs of their preprocessor config pb files into PREPROCESSOR_PB_TO_INSTALL.
# Config pb files that are used in unit test should be placed into
# PREPROCESSOR_PB_FOR_TEST.
PREPROCESSOR_PB_TO_INSTALL=(
	"gs://chromeos-localmirror/distfiles/mlservice-model-adaptive_charging-20211105-preprocessor.pb"
	"gs://chromeos-localmirror/distfiles/mlservice-model-adaptive_charging-20230314-preprocessor.pb"
)

PREPROCESSOR_PB_FOR_TEST=(
	"gs://chromeos-localmirror/distfiles/mlservice-model-smart_dim-20190521-preprocessor.pb"
)

SRC_URI="
	${DOWNLOADABLE_MODELS[*]}
	${MODELS_TO_INSTALL[*]}
	${PREPROCESSOR_PB_TO_INSTALL[*]}
	${PREPROCESSOR_PB_FOR_TEST[*]}
"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="
	dlc
	fuzzer
	internal
	march_alderlake
	ml_benchmark_drivers
	nnapi
	ondevice_document_scanner
	ondevice_document_scanner_dlc
	ondevice_grammar
	ondevice_handwriting
	ondevice_handwriting_dlc
	ondevice_speech
	ondevice_text_suggestions
	ondevice_image_content_annotation
	asan
	ubsan
"

RDEPEND="
	chromeos-base/chrome-icu:=
	>=chromeos-base/metrics-0.0.1-r3152:=
	chromeos-base/minijail:=
	internal? ( ondevice_speech? ( chromeos-soda/libsoda:=[dlc=] ) )
	nnapi? ( chromeos-base/aosp-frameworks-ml-nn )
	dlc? (
		ondevice_document_scanner_dlc? ( media-libs/cros-camera-document-scanner-dlc )
	)
	media-libs/cros-camera-libfs:=[ondevice_document_scanner=,ondevice_document_scanner_dlc=]
	>=dev-libs/libgrammar-0.0.4:=[ondevice_grammar=]
	dev-libs/libhandwriting:=[ondevice_handwriting=,ondevice_handwriting_dlc=]
	>=dev-libs/libsuggest-0.0.9:=[ondevice_text_suggestions=]
	>=dev-libs/libtextclassifier-0.0.1-r79:=
	sci-libs/tensorflow:=
	internal? ( ondevice_image_content_annotation? ( dev-libs/libica:= ) )
	dev-libs/ml-core:=
"

DEPEND="
	${RDEPEND}
	chromeos-base/system_api:=[fuzzer?]
	dev-cpp/abseil-cpp:=
	dev-libs/libutf:=
	dev-libs/marisa-aosp:=
	fuzzer? ( dev-libs/libprotobuf-mutator )
"

# SODA will not be supported on rootfs and only be supported through DLC.
REQUIRED_USE="ondevice_speech? ( dlc )"

src_install() {
	# platform_src_install omitted, to avoid conflict with
	# chromeos-base/ml-cmdline.
	# TODO(b/261604868): Resolve this conflict, where two ebuilds point at
	# the same BUILD.gn file.

	dobin "${OUT}"/ml_service

	# Install upstart configuration.
	insinto /etc/init
	doins init/*.conf

	# Install seccomp policy files.
	insinto /usr/share/policy
	newins "seccomp/ml_service-seccomp-${ARCH}.policy" ml_service-seccomp.policy
	newins "seccomp/ml_service-AdaptiveChargingModel-seccomp-${ARCH}.policy" ml_service-AdaptiveChargingModel-seccomp.policy
	newins "seccomp/ml_service-BuiltinModel-seccomp-${ARCH}.policy" ml_service-BuiltinModel-seccomp.policy
	newins "seccomp/ml_service-DocumentScanner-seccomp-${ARCH}.policy" ml_service-DocumentScanner-seccomp.policy
	newins "seccomp/ml_service-FlatBufferModel-seccomp-${ARCH}.policy" ml_service-FlatBufferModel-seccomp.policy
	newins "seccomp/ml_service-HandwritingModel-seccomp-${ARCH}.policy" ml_service-HandwritingModel-seccomp.policy
	newins "seccomp/ml_service-ImageAnnotator-seccomp-${ARCH}.policy" ml_service-ImageAnnotator-seccomp.policy
	newins "seccomp/ml_service-WebPlatformHandwritingModel-seccomp-${ARCH}.policy" ml_service-WebPlatformHandwritingModel-seccomp.policy
	newins "seccomp/ml_service-SodaModel-seccomp-${ARCH}.policy" ml_service-SodaModel-seccomp.policy
	newins "seccomp/ml_service-TextClassifierModel-seccomp-${ARCH}.policy" ml_service-TextClassifierModel-seccomp.policy
	newins "seccomp/ml_service-GrammarCheckerModel-seccomp-${ARCH}.policy" ml_service-GrammarCheckerModel-seccomp.policy
	newins "seccomp/ml_service-WebPlatformFlatBufferModel-seccomp-${ARCH}.policy" ml_service-WebPlatformFlatBufferModel-seccomp.policy

	# Install D-Bus configuration file.
	insinto /etc/dbus-1/system.d
	doins dbus/org.chromium.MachineLearning.conf

	# Install D-Bus service activation configuration.
	insinto /usr/share/dbus-1/system-services
	doins dbus/org.chromium.MachineLearning.service
	doins dbus/org.chromium.MachineLearning.AdaptiveCharging.service

	# Create distfile array of model filepaths.
	local model_files=( "${MODELS_TO_INSTALL[@]##*/}" "${PREPROCESSOR_PB_TO_INSTALL[@]##*/}" )
	local distfile_array=( "${model_files[@]/#/${DISTDIR}/}" )

	# Install system ML models.
	insinto /opt/google/chrome/ml_models
	doins "${distfile_array[@]}"

	# Install system ML models to fuzzer dir.
	insinto /usr/libexec/fuzzers
	doins "${distfile_array[@]}"

	# Install fuzzer targets.
	for fuzzer in "${OUT}"/*_fuzzer; do
		local fuzzer_component_id="187682"
		platform_fuzzer_install "${S}"/OWNERS "${fuzzer}" \
			--comp "${fuzzer_component_id}"
	done

	if use ml_benchmark_drivers; then
		insinto /usr/local/ml_benchmark/ml_service
		insopts -m0755
		doins "${OUT}"/lib/libml_for_benchmark.so
		insopts -m0644
	fi
}

pkg_preinst() {
	enewuser "ml-service"
	enewgroup "ml-service"
	enewuser "ml-service-dbus"
	enewgroup "ml-service-dbus"
}

platform_pkg_test() {
	# TODO(b/183455993): Re-enable when unit tests requiring instructions not
	# supported by the build machine can be run.
	if use march_alderlake; then
		return
	fi

	# Recreate model dir in the temp directory and copy both
	# MODELS_TO_INSTALL and DOWNLOADABLE_MODELS into it for use in unit
	# tests.
	mkdir "${T}/ml_models" || die
	local all_test_models=(
		"${DOWNLOADABLE_MODELS[@]}"
		"${MODELS_TO_INSTALL[@]}"
		"${PREPROCESSOR_PB_TO_INSTALL[@]}"
		"${PREPROCESSOR_PB_FOR_TEST[@]}"
	)
	local distfile_uri
	for distfile_uri in "${all_test_models[@]}"; do
		cp "${DISTDIR}/${distfile_uri##*/}" "${T}/ml_models" || die
	done

	local gtest_excl_filter="-"
	if use asan || use ubsan; then
		gtest_excl_filter+="SODARecognizerTest.*:"
	fi
	# TODO(b/261082064): disable to unblock chromeos-chrome & chrome-icu uprev.
	# Need a decent fix about ubsan issue with new chrome-icu.
	if use ubsan; then
		gtest_excl_filter+="TextClassifierAnnotateTest.*:"
	fi

	# The third argument equaling 1 means "run as root". This is needed for
	# multiprocess unit test.
	platform_test "run" "${OUT}/ml_service_test" 1 "${gtest_excl_filter}"
}
