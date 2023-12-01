# Copyright 2021 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..11} )

CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"
CROS_WORKON_PROJECT="external/github.com/llvm/llvm-project"
CROS_WORKON_LOCALNAME="llvm-project"
CROS_WORKON_MANUAL_UPREV=1

inherit cros-constants cmake-multilib git-2 flag-o-matic cros-llvm python-single-r1 toolchain-funcs cros-workon

DESCRIPTION="lldb-server, for the LLDB debugger"
HOMEPAGE="https://github.com/llvm/llvm-project"
SRC_URI=""
EGIT_REPO_URI="${CROS_GIT_HOST_URL}/external/github.com/llvm/llvm-project
	${CROS_GIT_HOST_URL}/external/github.com/llvm/llvm-project"
EGIT_BRANCH=main

LLVM_HASH="98f5a340975bc00197c57e39eb4ca26e2da0e8a2" # r496208
LLVM_NEXT_HASH="98f5a340975bc00197c57e39eb4ca26e2da0e8a2" # r496208

LICENSE="|| ( UoI-NCSA MIT )"
SLOT="0"
KEYWORDS="*"
if [[ "${PV}" == "9999" ]]; then
	KEYWORDS="~*"
fi
IUSE="cros_host llvm-next llvm-tot continue-on-patch-failure python"
RDEPEND="
	app-arch/zstd
	python? (
		$(python_gen_cond_dep '
			dev-python/six[${PYTHON_USEDEP}]
		')
		${PYTHON_DEPS}
	)
"

DEPEND="${RDEPEND}
	sys-libs/ncurses"

BDEPEND="
	${PYTHON_DEPS}
	>=dev-util/cmake-3.16
	python? (
		>=dev-lang/swig-3.0.11
		$(python_gen_cond_dep '
			dev-python/six[${PYTHON_USEDEP}]
		')
	)
"

# CMAKE_BUILD_TYPE and CMAKE_MAKEFILE_GENERATOR are called by
# cmake-utils_src_configure and cmake-utils_src_make (which is called
# from cmake-utils_src_compile), respectively (see
# third_party/portage-stable/eclass/cmake-utils.eclass.
# shellcheck disable=SC2034
CMAKE_BUILD_TYPE=Release
# shellcheck disable=SC2034
CMAKE_MAKEFILE_GENERATOR=ninja

pkg_setup() {
	use cros_host && die "lldb is not supported for building on non-device builds"
	python-single-r1_pkg_setup
	# Setup llvm toolchain for cross-compilation.
	setup_cross_toolchain
	export CMAKE_USE_DIR="${S}/lldb"
}

src_unpack() {
	if use llvm-next || use llvm-tot; then
		export EGIT_COMMIT="${LLVM_NEXT_HASH}"
	else
		export EGIT_COMMIT="${LLVM_HASH}"
	fi
	if [[ "${PV}" != "9999" ]]; then
		CROS_WORKON_COMMIT="${EGIT_COMMIT}"
	fi
	cros-workon_src_unpack
}

src_prepare() {
	cmake-utils_src_prepare
	local failure_mode
	failure_mode="$(usex continue-on-patch-failure continue fail)"
	"${FILESDIR}"/patch_manager/patch_manager.py \
		--svn_version "$(get_most_recent_revision)" \
		--patch_metadata_file "${FILESDIR}"/PATCHES.json \
		--failure_mode "${failure_mode}" \
		--src_path "${S}" || die

	eapply_user
}

build_llvm_host() {
	echo "Building host llvm tools"
	mkdir llvm_build_host
	pushd llvm_build_host || die
	local libdir=$(get_libdir)
	local mycmakeargs=(
		"${mycmakeargs[@]}"
		"-DLLVM_ENABLE_PROJECTS=llvm;clang;lldb"
		"-DLLVM_LIBDIR_SUFFIX=${libdir#lib}"
		"-DCMAKE_BUILD_TYPE=RelWithDebInfo"
		"-DCMAKE_INSTALL_PREFIX=${PREFIX}"
		"-DLLVM_TARGETS_TO_BUILD=X86"
		"-DLLVM_BUILD_TOOLS=OFF"
		"-DLLVM_BUILD_TESTS=OFF"
		"-DLLVM_INCLUDE_TESTS=OFF"
		"-DLLVM_INCLUDE_DOCS=OFF"
		"-DLLVM_INCLUDE_UTILS=OFF"
		"-DLLVM_BUILD_UTILS=OFF"
		"-DLLVM_USE_HOST_TOOLS=OFF"
		"-DLLVM_ENABLE_ZLIB=OFF"
		"-DLLVM_BUILD_TESTS=OFF"
		"-DLLVM_INCLUDE_TESTS=OFF"
		"-DLLVM_INCLUDE_DOCS=OFF"
		"-DLLVM_INCLUDE_UTILS=OFF"
		"-DLLVM_BUILD_UTILS=OFF"
		"-DLLVM_USE_HOST_TOOLS=OFF"
		"-DLLVM_ENABLE_ZLIB=OFF"
		"-DCLANG_BUILD_TOOLS=OFF"
		"-DCLANG_ENABLE_ARCMT=OFF"
		"-DCLANG_ENABLE_STATIC_ANALYZER=OFF"
		"-DCLANG_INCLUDE_TESTS=OFF"
		"-DCLANG_INCLUDE_DOCS=OFF"
		"-DLLVM_ENABLE_IDE=ON"
		"-DLLVM_ENABLE_ZSTD=OFF"
		"-DLLVM_ADD_NATIVE_VISUALIZERS_TO_SOLUTION=OFF"
		"-DCLANG_LINK_CLANG_DYLIB=OFF"
		"-DLLVM_BUILD_LLVM_DYLIB=OFF"
		"-DLLVM_LINK_LLVM_DYLIB=OFF"
		"-DLLVM_INCLUDE_EXAMPLES=OFF"
		"-DLLVM_INCLUDE_RUNTIMES=OFF"
		"-DLLVM_INCLUDE_BENCHMARKS=OFF"
		"-DLLDB_ENABLE_PYTHON=OFF"
		"-DLLDB_ENABLE_LIBEDIT=OFF"
		"-DLLDB_ENABLE_CURSES=OFF"
		"-DPython3_EXECUTABLE=${PYTHON}"
	)
	tc-env_build cmake -GNinja "${mycmakeargs[@]}" "${S}/llvm" || die
	ninja llvm-tblgen clang-tblgen lldb-tblgen || die
	popd || die
}

build_llvm_libs() {
	echo "Cross-compiling llvm and clang libraries"
	mkdir llvm_build
	pushd llvm_build || die
	local libdir=$(get_libdir)
	local mycmakeargs=(
		"${mycmakeargs[@]}"
		"-DLLVM_ENABLE_PROJECTS=llvm;clang"
		"-DLLVM_LIBDIR_SUFFIX=${libdir#lib}"
		"-DLLVM_TARGETS_TO_BUILD=X86;ARM;AArch64"
		"-DCMAKE_INSTALL_PREFIX=${PREFIX}"
		"-DCMAKE_CROSSCOMPILING=ON"
		"-DCMAKE_BUILD_TYPE=RelWithDebInfo"
		"-DLLVM_BUILD_TOOLS=OFF"
		"-DLLDB_EXTERNAL_CLANG_RESOURCE_DIR=$(tc-getCC --print-resource-dir)"
		"-DLLDB_INCLUDE_TESTS=OFF"
		"-DLLVM_TABLEGEN=../llvm_build_host/bin/llvm-tblgen"
		"-DCLANG_TABLEGEN=../llvm_build_host/bin/clang-tblgen"
		"-DLLVM_BUILD_TESTS=OFF"
		"-DLLVM_INCLUDE_TESTS=OFF"
		"-DLLVM_INCLUDE_DOCS=OFF"
		"-DLLVM_INCLUDE_UTILS=OFF"
		"-DLLVM_BUILD_UTILS=OFF"
		"-DLLVM_USE_HOST_TOOLS=OFF"
		"-DLLVM_ENABLE_ZLIB=OFF"
		"-DLLVM_ENABLE_ZSTD=OFF"
		"-DCLANG_BUILD_TOOLS=OFF"
		"-DCLANG_ENABLE_ARCMT=OFF"
		"-DCLANG_ENABLE_STATIC_ANALYZER=OFF"
		"-DCLANG_INCLUDE_TESTS=OFF"
		"-DCLANG_INCLUDE_DOCS=OFF"
		"-DLLVM_ENABLE_IDE=ON"
		"-DLLVM_ADD_NATIVE_VISUALIZERS_TO_SOLUTION=OFF"
		"-DCLANG_LINK_CLANG_DYLIB=OFF"
		"-DLLVM_BUILD_LLVM_DYLIB=OFF"
		"-DLLVM_LINK_LLVM_DYLIB=OFF"
		"-DLLVM_INCLUDE_EXAMPLES=OFF"
		"-DLLVM_INCLUDE_RUNTIMES=OFF"
		"-DLLVM_INCLUDE_BENCHMARKS=OFF"
		"-DLLDB_ENABLE_PYTHON=OFF"
		"-DLLDB_ENABLE_LIBEDIT=OFF"
		"-DLLDB_ENABLE_CURSES=OFF"
		"-DPython3_EXECUTABLE=${PYTHON}"
	)
	cmake -GNinja "${mycmakeargs[@]}" "${S}/llvm" || die
	# shellcheck disable=SC2034
	local clangLibs=(
		libclangAST.a
		libclangCodeGen.a
		libclangDriver.a
		libclangEdit.a
		libclangFrontend.a
		libclangLex.a
		libclangParse.a
		libclangRewrite.a
		libclangRewriteFrontend.a
		libclangSema.a
		libclangSerialization.a
	)
	# shellcheck disable=SC2034
	local llvmLibs=(
		libLLVMCore.a
		libLLVMExecutionEngine.a
		libLLVMipo.a
		libLLVMMCJIT.a
		libLLVMDebugInfoDWARF.a
		libLLVMDemangle.a
		libLLVMBinaryFormat.a
		libLLVMDebugInfoPDB.a
	)
	# reduced list of targets but fragile.
	ninja llvm-config clang-headers llvm-headers "${clangLibs[@]}" "${llvmLibs[@]}" || die
	# May want to use llvm-libraries clang-libraries instead but that will build
	# to many redundant files.
	popd || die
}

src_configure() {
	build_llvm_host
	build_llvm_libs
	local libdir=$(get_libdir)
	local mycmakeargs=(
		"${mycmakeargs[@]}"
		"-DLLVM_LIBDIR_SUFFIX=${libdir#lib}"
		"-DCMAKE_INSTALL_PREFIX=${PREFIX}"
		"-DLLVM_TARGETS_TO_BUILD=X86;ARM;AArch64"
		"-DLLDB_EXTERNAL_CLANG_RESOURCE_DIR=$(tc-getCC --print-resource-dir)"
		"-DLLDB_INCLUDE_TESTS=OFF"
		"-DCMAKE_CROSSCOMPILING=ON"
		"-DLLVM_BUILD_TESTS=OFF"
		"-DLLVM_INCLUDE_TESTS=OFF"
		"-DLLVM_INCLUDE_DOCS=OFF"
		"-DLLVM_INCLUDE_UTILS=OFF"
		"-DLLVM_BUILD_UTILS=OFF"
		"-DLLVM_USE_HOST_TOOLS=OFF"
		"-DLLDB_ENABLE_LUA=OFF"
		"-DLLVM_ENABLE_IDE=ON"
		"-DLLDB_ENABLE_PYTHON=OFF"
		"-DLLDB_ENABLE_LIBEDIT=OFF"
		"-DLLDB_ENABLE_CURSES=OFF"
		"-DLLDB_TABLEGEN_EXE=${PWD}/llvm_build_host/bin/lldb-tblgen"
		"-DLLVM_TABLEGEN=${PWD}/llvm_build_host/bin/llvm-tblgen"
		"-DLLVM_DIR=${PWD}/llvm_build/lib/cmake/llvm"
		"-DLLVM_BINARY_DIR=${PWD}/llvm_build"
		"-DLLVM_HOST_TRIPLE=${CHOST}"
		"-DPython3_EXECUTABLE=${PYTHON}"
	)

	append-cppflags "-I${S}/llvm/include"
	append-cppflags "-I${S}/clang/include"
	append-cppflags "-I${PWD}/llvm_build/include"
	append-cppflags "-I${PWD}/llvm_build/tools/clang/include"
	append-ldflags "-L${PWD}/llvm_build/lib"
	append-ldflags "-L${PWD}/llvm_build/tools/clang/lib"

	echo "configuring lldb"
	cmake-utils_src_configure
}

src_compile() {
	cmake-utils_src_compile lldb-server
}

src_install() {
	# shellcheck disable=SC2154
	dobin "${BUILD_DIR}"/bin/lldb-server
}
