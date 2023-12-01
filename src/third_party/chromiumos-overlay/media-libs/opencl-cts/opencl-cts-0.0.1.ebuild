# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake-utils

DESCRIPTION="The OpenCL Conformance Tests"
HOMEPAGE="https://github.com/KhronosGroup/OpenCL-CTS"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

OPENCL_CTS="OpenCL-CTS-2023-05-16-00"
SRC_URI="https://storage.googleapis.com/chromeos-localmirror/distfiles/${OPENCL_CTS}.zip"

# target build dependencies
DEPEND="
	>=dev-util/opencl-headers-2021.04.29
	>=media-libs/clvk-0.0.1
"

# target runtime dependencies
RDEPEND="
	>=media-libs/clvk-0.0.1
"

# host build dependencies
BDEPEND="
	>=dev-util/cmake-3.13.4
"

S="${WORKDIR}/${OPENCL_CTS}"

PATCHES=(
	"${FILESDIR}/test_compiler.patch"
)

src_prepare() {
	cros_enable_cxx_exceptions
	cmake-utils_src_prepare
	eapply_user
}

src_configure() {
	local mycmakeargs=(
		-DCL_LIB_DIR="${ESYSROOT}/usr/$(get_libdir)"
		-DCL_INCLUDE_DIR="${ESYRSOOT}/usr/include"
		-DOPENCL_LIBRARIES="-lOpenCL"
	)
	cmake-utils_src_configure
}

src_install() {
	local OPENCL_TESTS_DIR="/usr/local/opencl"
	dodir "${OPENCL_TESTS_DIR}"
	exeinto "${OPENCL_TESTS_DIR}"

	doexe "${BUILD_DIR}/test_conformance/allocations/test_allocations"
	doexe "${BUILD_DIR}/test_conformance/api/test_api"
	doexe "${BUILD_DIR}/test_conformance/atomics/test_atomics"
	doexe "${BUILD_DIR}/test_conformance/basic/test_basic"
	doexe "${BUILD_DIR}/test_conformance/buffers/test_buffers"
	doexe "${BUILD_DIR}/test_conformance/c11_atomics/test_c11_atomics"
	doexe "${BUILD_DIR}/test_conformance/commonfns/test_commonfns"
	doexe "${BUILD_DIR}/test_conformance/compiler/test_compiler"
	doexe "${BUILD_DIR}/test_conformance/computeinfo/test_computeinfo"
	doexe "${BUILD_DIR}/test_conformance/contractions/test_contractions"
	doexe "${BUILD_DIR}/test_conformance/conversions/test_conversions"
	doexe "${BUILD_DIR}/test_conformance/device_timer/test_device_timer"
	doexe "${BUILD_DIR}/test_conformance/events/test_events"
	doexe "${BUILD_DIR}/test_conformance/generic_address_space/test_generic_address_space"
	doexe "${BUILD_DIR}/test_conformance/geometrics/test_geometrics"
	doexe "${BUILD_DIR}/test_conformance/half/test_half"
	doexe "${BUILD_DIR}/test_conformance/images/clCopyImage/test_cl_copy_images"
	doexe "${BUILD_DIR}/test_conformance/images/clFillImage/test_cl_fill_images"
	doexe "${BUILD_DIR}/test_conformance/images/clGetInfo/test_cl_get_info"
	doexe "${BUILD_DIR}/test_conformance/images/clReadWriteImage/test_cl_read_write_images"
	doexe "${BUILD_DIR}/test_conformance/images/kernel_image_methods/test_kernel_image_methods"
	doexe "${BUILD_DIR}/test_conformance/images/kernel_read_write/test_image_streams"
	doexe "${BUILD_DIR}/test_conformance/images/samplerlessReads/test_samplerless_reads"
	doexe "${BUILD_DIR}/test_conformance/integer_ops/test_integer_ops"
	doexe "${BUILD_DIR}/test_conformance/math_brute_force/test_bruteforce"
	doexe "${BUILD_DIR}/test_conformance/mem_host_flags/test_mem_host_flags"
	doexe "${BUILD_DIR}/test_conformance/multiple_device_context/test_multiples"
	doexe "${BUILD_DIR}/test_conformance/non_uniform_work_group/test_non_uniform_work_group"
	doexe "${BUILD_DIR}/test_conformance/printf/test_printf"
	doexe "${BUILD_DIR}/test_conformance/profiling/test_profiling"
	doexe "${BUILD_DIR}/test_conformance/relationals/test_relationals"
	doexe "${BUILD_DIR}/test_conformance/select/test_select"
	doexe "${BUILD_DIR}/test_conformance/thread_dimensions/test_thread_dimensions"
	doexe "${BUILD_DIR}/test_conformance/vectors/test_vectors"
	doexe "${BUILD_DIR}/test_conformance/workgroups/test_workgroups"
}
