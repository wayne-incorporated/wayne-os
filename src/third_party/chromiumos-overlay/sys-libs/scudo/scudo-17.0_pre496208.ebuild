# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"
CROS_WORKON_PROJECT="external/github.com/llvm/llvm-project"
CROS_WORKON_LOCALNAME="llvm-project"
CROS_WORKON_MANUAL_UPREV=1

inherit eutils toolchain-funcs cros-constants cmake-utils git-2 cros-llvm cros-workon

EGIT_REPO_URI="${CROS_GIT_HOST_URL}/external/github.com/llvm/llvm-project
	${CROS_GIT_HOST_URL}/external/github.com/llvm/llvm-project"
EGIT_BRANCH=main

LLVM_HASH="98f5a340975bc00197c57e39eb4ca26e2da0e8a2" # r496208
LLVM_NEXT_HASH="98f5a340975bc00197c57e39eb4ca26e2da0e8a2" # r496208

DESCRIPTION="LLVM scudo_standalone memory allocator"
HOMEPAGE="http://compiler-rt.llvm.org/"

LICENSE="UoI-NCSA"
SLOT="0"
KEYWORDS="*"
if [[ "${PV}" == "9999" ]]; then
	KEYWORDS="~*"
fi
IUSE="llvm-next llvm-tot continue-on-patch-failure system_wide_scudo"
DEPEND="sys-libs/libxcrypt"

pkg_setup() {
	export CMAKE_USE_DIR="${S}/compiler-rt"
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
	local failure_mode
	failure_mode="$(usex continue-on-patch-failure continue fail)"
	"${FILESDIR}"/patch_manager/patch_manager.py \
		--svn_version "$(get_most_recent_revision)" \
		--patch_metadata_file "${FILESDIR}"/PATCHES.json \
		--failure_mode "${failure_mode}" \
		--src_path "${S}" || die

	eapply_user
	cmake-utils_src_prepare
}

src_configure() {
	BUILD_DIR="${WORKDIR}/${P}_build"
	append-lfs-flags
	append-flags -DUSE_CHROMEOS_CONFIG

	local mycmakeargs=(
		"-DCOMPILER_RT_BUILD_CRT=no"
		"-DCOMPILER_RT_USE_LIBCXX=yes"
		"-DCOMPILER_RT_LIBCXXABI_PATH=${S}/libcxxabi"
		"-DCOMPILER_RT_LIBCXX_PATH=${S}/libcxx"
		"-DCOMPILER_RT_HAS_GNU_VERSION_SCRIPT_COMPAT=no"
		"-DCOMPILER_RT_BUILTINS_HIDE_SYMBOLS=OFF"
		"-DCOMPILER_RT_BUILD_SANITIZERS=yes"
		"-DCOMPILER_RT_BUILD_LIBFUZZER=no"
		"-DCOMPILER_RT_DEFAULT_TARGET_TRIPLE=${CTARGET}"
		"-DCOMPILER_RT_TEST_TARGET_TRIPLE=${CTARGET}"

		# We require gwp_asan as we want it built within the scudo dso
		"-DCOMPILER_RT_SANITIZERS_TO_BUILD=scudo_standalone;gwp_asan"
		"-DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF"
		"-DCOMPILER_RT_BUILD_ORC=OFF"
		"-DCOMPILER_RT_INSTALL_PATH=${EPREFIX}$(${CC} --print-resource-dir)"
	)

	cmake-utils_src_configure
}

src_install() {
	local arch
	case "${ARCH}" in
		x86) arch='i386';;
		amd64) arch='x86_64';;
		arm) arch='armhf';;
		arm64) arch='aarch64';;
		*) die "unknown ARCH '${ARCH}'";;
	esac

	# Install the scudo_standalone .so
	local libname="libclang_rt.scudo_standalone-${arch}.so"
	dolib.so "${BUILD_DIR}/lib/linux/${libname}"
}
