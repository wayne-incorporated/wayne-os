# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

if [[ ${PV} != "9999" ]]; then
	CROS_WORKON_COMMIT=(
		"f147173e345d9fc66b2a49e638b5b47913aae298"
		"2deff0bbbedec3b08231280cf71f185c0c4456b3"
	)
fi

CROS_WORKON_MANUAL_UPREV="1"

CROS_WORKON_PROJECT=(
	"chromiumos/third_party/clvk"
	"chromiumos/third_party/clspv"
)

CROS_WORKON_LOCALNAME=(
	"clvk"
	"clspv"
)

CLVK_DIR="${S}/clvk"
CLSPV_DIR="${S}/clspv"

CROS_WORKON_DESTDIR=(
	"${CLVK_DIR}"
	"${CLSPV_DIR}"
)

CROS_WORKON_EGIT_BRANCH=(
	"upstream/main"
	"upstream/main"
)

inherit cmake-utils cros-workon

CMAKE_USE_DIR="${CLVK_DIR}"

DESCRIPTION="Prototype implementation of OpenCL 1.2 on to of Vulkan using clspv as the Compiler"
HOMEPAGE="https://github.com/kpet/${PN}"

LLVM_FOLDER="llvm-project-62110aabc91d784b2a3a619e675c2830fa623c1e"
LLVM_ARCHIVE="${LLVM_FOLDER}.zip"

SRC_URI="
https://storage.cloud.google.com/chromeos-localmirror/distfiles/${LLVM_ARCHIVE}
"

LICENSE="Apache-2.0"
SLOT="0"
if [[ ${PV} != "9999" ]]; then
	KEYWORDS="*"
else
	KEYWORDS="~*"
fi
IUSE="debug +perfetto"

VK_SPV_VERSION="1.3.243"

# target runtime dependencies
RDEPEND="
	>=dev-util/spirv-tools-${VK_SPV_VERSION}
	>=media-libs/vulkan-loader-${VK_SPV_VERSION}
"

# target build dependencies
DEPEND="
	>=dev-util/vulkan-headers-${VK_SPV_VERSION}
	>=dev-util/spirv-headers-${VK_SPV_VERSION}
	>=dev-util/opencl-headers-2023.02.06
	>=chromeos-base/perfetto-31.0
	${RDEPEND}
"

# host build dependencies
BDEPEND="
	>=dev-util/cmake-3.13.4
"

PATCHES=()
if [[ ${PV} != "9999" ]]; then
	PATCHES+=("${FILESDIR}/clvk-00-opencl12.patch")
	# TODO(b/241788717) : To be remove once we have a proper implementation for it in clvk
	PATCHES+=("${FILESDIR}/clvk-01-sampledbuffer.patch")

	# TODO(b/259217927) : To be remove as soon as they are merged upstream
	PATCHES+=("${FILESDIR}/clvk-11-multi-command-event.patch")
	PATCHES+=("${FILESDIR}/clvk-90-timeline-semaphores.patch")
	PATCHES+=("${FILESDIR}/clvk-91-configurable-polling.patch")
fi

src_unpack() {
	unpack "${LLVM_ARCHIVE}"
	cros-workon_src_unpack
}

src_prepare() {
	cmake-utils_src_prepare
	eapply_user
}

build_host_tools() {
	[[ "$#" -eq 2 ]] \
		|| die "build_host_tools called with the wrong number of arguments"
	local HOST_DIR="$1"
	local LLVM_DIR="$2"

	# Use host toolchain when building for the host.
	local CC=${CBUILD}-clang
	local CXX=${CBUILD}-clang++
	local CFLAGS=''
	local CXXFLAGS=''
	local LDFLAGS=''

	mkdir -p "${HOST_DIR}" || die

	cd "${HOST_DIR}" || die
	cmake \
		-DLLVM_TARGETS_TO_BUILD="" \
		-DLLVM_OPTIMIZED_TABLEGEN=ON \
		-DLLVM_INCLUDE_BENCHMARKS=OFF \
		-DLLVM_INCLUDE_EXAMPLES=OFF \
		-DLLVM_INCLUDE_TESTS=OFF \
		-DLLVM_ENABLE_BINDINGS=OFF \
		-DLLVM_ENABLE_UNWIND_TABLES=OFF \
		-DLLVM_BUILD_TOOLS=OFF \
		-G "Unix Makefiles" \
		-DLLVM_ENABLE_PROJECTS="clang" \
		-DCMAKE_BUILD_TYPE=Release \
		"${LLVM_DIR}" || die

	cd "${HOST_DIR}/utils/TableGen" || die
	emake
	[[ -x "${HOST_DIR}/bin/llvm-tblgen" ]] \
		|| die "${HOST_DIR}/bin/llvm-tblgen not found or usable"

	cd "${HOST_DIR}/tools/clang/utils/TableGen" || die
	emake
	[[ -x "${HOST_DIR}/bin/clang-tblgen" ]] \
		|| die "${HOST_DIR}/bin/clang-tblgen not found or usable"
}

src_configure() {
	CMAKE_BUILD_TYPE=$(usex debug Debug RelWithDebInfo)

	local CLVK_LLVM_PROJECT_DIR="${WORKDIR}/${LLVM_FOLDER}"
	local mycmakeargs=(
		-DSPIRV_HEADERS_SOURCE_DIR="${ESYSROOT}/usr/"
		-DSPIRV_TOOLS_SOURCE_DIR="${ESYSROOT}/usr/"

		-DLLVM_INCLUDE_BENCHMARKS=OFF
		-DLLVM_INCLUDE_EXAMPLES=OFF
		-DLLVM_INCLUDE_TESTS=OFF
		-DLLVM_ENABLE_BINDINGS=OFF
		-DLLVM_ENABLE_UNWIND_TABLES=OFF
		-DLLVM_BUILD_TOOLS=OFF

		-DCLSPV_SOURCE_DIR="${CLSPV_DIR}"
		-DCLSPV_LLVM_SOURCE_DIR="${CLVK_LLVM_PROJECT_DIR}/llvm"
		-DCLSPV_CLANG_SOURCE_DIR="${CLVK_LLVM_PROJECT_DIR}/clang"

		-DCLVK_CLSPV_ONLINE_COMPILER=1
		-DCLVK_ENABLE_SPIRV_IL=OFF

		-DCLSPV_BUILD_SPIRV_DIS=OFF
		-DCLSPV_BUILD_TESTS=OFF
		-DCLVK_BUILD_TESTS=OFF
		-DCLVK_BUILD_SPIRV_TOOLS=OFF

		-DCLVK_VULKAN_IMPLEMENTATION=system

		-DCMAKE_MODULE_PATH="${CMAKE_MODULE_PATH};${CLVK_LLVM_PROJECT_DIR}/llvm/cmake/modules"

		-DBUILD_SHARED_LIBS=OFF

		-DCLVK_PERFETTO_ENABLE=$(usex perfetto ON OFF)
		-DCLVK_PERFETTO_LIBRARY=perfetto_sdk
		-DCLVK_PERFETTO_BACKEND=System
		-DCLVK_PERFETTO_SDK_DIR="${ESYSROOT}/usr/include/perfetto/"
	)

	if [[ ${PV} == "9999" ]]; then
		mycmakeargs+=(
			-DCLVK_ENABLE_ASSERTIONS=ON
		)
	fi

	if tc-is-cross-compiler; then
		local HOST_DIR="${WORKDIR}/host_tools"
		build_host_tools "${HOST_DIR}" "${CLVK_LLVM_PROJECT_DIR}/llvm"
		mycmakeargs+=(
			-DCMAKE_CROSSCOMPILING=ON
			-DLLVM_TABLEGEN="${HOST_DIR}/bin/llvm-tblgen"
			-DCLANG_TABLEGEN="${HOST_DIR}/bin/clang-tblgen"
		)
	fi

	cmake-utils_src_configure
}

src_install() {
	dolib.so "${BUILD_DIR}/libOpenCL.so"*
}
