# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake-utils flag-o-matic git-r3

DESCRIPTION="Intel OpenVino Toolkit with VPUX support"
HOMEPAGE="https://github.com/openvinotoolkit/openvino"
SRC_URI="gs://chromeos-localmirror/distfiles/$P-files.tar.xz"

LICENSE="Apache-2.0"
KEYWORDS="-* amd64"
IUSE="+clang"
SLOT="0"

RDEPEND="
	dev-libs/protobuf
	media-libs/opencv
	dev-cpp/gflags
"

DEPEND="
	${RDEPEND}
"

CMAKE_BUILD_TYPE="Release"

src_unpack() {
	EGIT_REPO_URI="https://github.com/openvinotoolkit/openvino.git" \
	EGIT_CHECKOUT_DIR="${S}" \
	EGIT_COMMIT="2022.3.0" \
	git-r3_src_unpack

	EGIT_REPO_URI="https://github.com/openvinotoolkit/vpux_plugin" \
	EGIT_CHECKOUT_DIR="${S}/../vpux_plugin" \
	EGIT_COMMIT="vpu_chrome_alpha_rc1" \
	git-r3_src_unpack
}

src_prepare() {
	eapply "${FILESDIR}/0001-Enable-build-for-ChromeOS.patch"
	eapply "${FILESDIR}/0002-Fix-OpenVINO-2022.3.0-compile-issues.patch"
	eapply "${FILESDIR}/0001-Build-legacy-as-static-lib.patch"
	eapply "${FILESDIR}/0003-Install-libs-ChromeOS.patch"
	cros_enable_cxx_exceptions
	eapply_user
	unpack ${DISTDIR}/$P-files.tar.xz
	unpack ${S}/vpux-plugin-lfs-files.tar.gz
	cp -r "${S}"/act_shave_bin/*.elf "${S}"/../vpux_plugin/sw_runtime_kernels/kernels/prebuild/act_shave_bin
	cp "${S}/profiling-0-37XX-MVN.bin" "${S}/../vpux_plugin/tests/lit/VPUX37XX/data"
	cp "${S}/profiling-0-37XX-PLL-10.bin" "${S}/../vpux_plugin/tests/lit/VPUX37XX/data"
	cp "${S}/profiling-0-37XX.bin" "${S}/../vpux_plugin/tests/lit/VPUX37XX/data"
	cp "${S}/vpu_2_0.vpunn" "${S}/../vpux_plugin/thirdparty/vpucostmodel/models"
	cp "${S}/vpu_2_7.vpunn" "${S}/../vpux_plugin/thirdparty/vpucostmodel/models"
	cmake-utils_src_prepare
}

src_configure() {
	cros_enable_cxx_exceptions
	append-flags "-Wno-undef -frtti -fvisibility=default -Wno-macro-redefined -D__CHROMIUMOS__ -Wno-unqualified-std-cast-call"

	local mycmakeargs=(
		-DCMAKE_BUILD_TYPE=Release
		-DCMAKE_INSTALL_PREFIX="/usr/local/"
		-DTARGET_OS_NAME="CHROMIUMOS"
		-DENABLE_OV_TF_FRONTEND=OFF
		-DENABLE_OV_ONNX_FRONTEND=OFF
		-DENABLE_OV_PADDLE_FRONTEND=OFF
		-DENABLE_INTEL_GPU=OFF
		-DENABLE_INTEL_GNA=OFF
		-DENABLE_INTEL_MYRIAD_COMMON=OFF
		-DENABLE_MULTI=OFF
		-DENABLE_AUTO=OFF
		-DDNNL_ENABLE_WORKLOAD="INFERENCE"
		-DENABLE_NCC_STYLE=OFF
		-DTHREADING=SEQ
		-DENABLE_PYTHON=OFF
	)
	cmake-utils_src_configure
}

src_install() {
	cmake-utils_src_install

	cd "${S}"/../vpux_plugin || die
	mkdir "${S}"/../vpux_plugin/build || die
	cd "${S}"/../vpux_plugin/build || die
	append-flags "-frtti -Wno-error,-Wno-dtor-name -I"${S}"/samples/cpp/common/format_reader -w"
	cmake -DInferenceEngineDeveloperPackage_DIR=${BUILD_DIR} \
		-DCMAKE_BUILD_TYPE=Release \
		-DTARGET_OS_NAME="CHROMIUMOS" \
		-DENABLE_DEVELOPER_BUILD=ON ..
	emake

	exeinto /usr/local/bin
	doexe ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/hello_query_device
	doexe ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/benchmark_app
	doexe ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/hello_classification
	doexe ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/classification_sample_async
	doexe ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/speech_sample
	doexe ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/compile_tool

	into /usr/local
	dolib.so ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/libformat_reader.so
	dolib.so ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/libvpux_mlir_compiler.so
	dolib.so ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/libvpux_level_zero_backend.so
	dolib.so ${S}/bin/intel64/${CMAKE_BUILD_TYPE}/libopenvino_intel_vpux_plugin.so
	dolib.so ${FILESDIR}/plugins.xml
}
