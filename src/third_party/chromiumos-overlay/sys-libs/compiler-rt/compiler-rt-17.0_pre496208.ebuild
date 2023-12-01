# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )

CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"
CROS_WORKON_PROJECT="external/github.com/llvm/llvm-project"
CROS_WORKON_LOCALNAME="llvm-project"
CROS_WORKON_MANUAL_UPREV=1

inherit eutils toolchain-funcs cros-constants cmake-utils git-2 cros-llvm cros-workon python-single-r1

EGIT_REPO_URI="${CROS_GIT_HOST_URL}/external/github.com/llvm/llvm-project
	${CROS_GIT_HOST_URL}/external/github.com/llvm/llvm-project"
EGIT_BRANCH=main

LLVM_HASH="98f5a340975bc00197c57e39eb4ca26e2da0e8a2" # r496208
LLVM_NEXT_HASH="98f5a340975bc00197c57e39eb4ca26e2da0e8a2" # r496208

DESCRIPTION="Compiler runtime library for clang"
HOMEPAGE="http://compiler-rt.llvm.org/"

LICENSE="UoI-NCSA"
SLOT="0"
KEYWORDS="*"
if [[ "${PV}" == "9999" ]]; then
	KEYWORDS="~*"
fi
IUSE="+llvm-crt llvm-next llvm-tot continue-on-patch-failure"
BDEPEND="sys-devel/llvm"
if [[ ${CATEGORY} == cross-* ]] ; then
	BDEPEND+="
		${CATEGORY}/binutils
		"
fi
if [[ ${CATEGORY} == cross-*linux-gnu* ]] ; then
	DEPEND+="
		${CATEGORY}/libxcrypt
		${CATEGORY}/linux-headers
	"
fi

pkg_setup() {
	# Since compiler-rt is moving to runtimes,
	# we should build with CMAKE there.
	export CMAKE_USE_DIR="${S}/runtimes"
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
	python_setup

	local failure_mode
	failure_mode="$(usex continue-on-patch-failure continue fail)"
	"${FILESDIR}"/patch_manager/patch_manager.py \
		--svn_version "$(get_most_recent_revision)" \
		--patch_metadata_file "${FILESDIR}"/PATCHES.json \
		--failure_mode "${failure_mode}" \
		--src_path "${S}" || die
	cmake-utils_src_prepare
}

src_configure() {
	setup_cross_toolchain
	append-flags "-fomit-frame-pointer"
	# CTARGET is defined in an eclass, which shellcheck won't see
	# shellcheck disable=SC2154
	if [[ ${CTARGET} == armv7a* ]]; then
		# Use vfpv3 to be able to target non-neon targets
		append-flags -mfpu=vfpv3
	fi
	BUILD_DIR=${WORKDIR}/${P}_build

	local mycmakeargs=(
		"-DLLVM_ENABLE_RUNTIMES=compiler-rt"
		"-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY"
		# crbug/855759
		"-DCOMPILER_RT_BUILD_CRT=$(usex llvm-crt)"
		"-DCOMPILER_RT_USE_LIBCXX=yes"
		"-DCOMPILER_RT_LIBCXXABI_PATH=${S}/libcxxabi"
		"-DCOMPILER_RT_LIBCXX_PATH=${S}/libcxx"
		"-DCOMPILER_RT_HAS_GNU_VERSION_SCRIPT_COMPAT=no"
		"-DCOMPILER_RT_BUILTINS_HIDE_SYMBOLS=OFF"
		"-DCOMPILER_RT_SANITIZERS_TO_BUILD=asan;msan;hwasan;tsan;cfi;ubsan_minimal;gwp_asan"
		# b/200831212: Disable per runtime install dirs.
		"-DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF"
		# b/204220308: Disable ORC since we are not using it.
		"-DCOMPILER_RT_BUILD_ORC=OFF"
		"-DCOMPILER_RT_INSTALL_PATH=${EPREFIX}$(${CC} --print-resource-dir)"
	)

	if is_baremetal_abi; then
		# Options for baremetal toolchains e.g. armv7m-cros-eabi.
		append-flags -Oz # Optimize for smallest size.

		mycmakeargs+=(
			"-DCMAKE_POSITION_INDEPENDENT_CODE=OFF"
			"-DCOMPILER_RT_BUILTINS_ENABLE_PIC=OFF"
			"-DCOMPILER_RT_OS_DIR=baremetal"
			"-DCOMPILER_RT_BAREMETAL_BUILD=yes"
			"-DCMAKE_C_COMPILER_TARGET=${CTARGET}"
			"-DCOMPILER_RT_DEFAULT_TARGET_ONLY=yes"
			"-DCOMPILER_RT_BUILD_CRT=OFF"
			"-DCOMPILER_RT_BUILD_SANITIZERS=no"
			"-DCOMPILER_RT_BUILD_LIBFUZZER=no"
		)
		# b/205342596: This is a hack to provide armv6m builtins for use with
		# arm-none-eabi without creating a separate armv6m toolchain.
		if [[ ${CTARGET} == arm-none-eabi ]]; then
			append-flags "-march=armv6m --sysroot=/usr/arm-none-eabi"
			mycmakeargs+=( "-DCMAKE_C_COMPILER_TARGET=armv6m-none-eabi" )
		elif [[ "${CTARGET}" == armv7m-cros-eabi ]]; then
			# b/286910996: Set target-specific floating point flags.
			append-flags -mcpu=cortex-m4
			append-flags -mfloat-abi=hard
		fi
	else
		# Standard userspace toolchains e.g. armv7a-cros-linux-gnueabihf.
		mycmakeargs+=(
			"-DCOMPILER_RT_DEFAULT_TARGET_TRIPLE=${CTARGET}"
			"-DCOMPILER_RT_TEST_TARGET_TRIPLE=${CTARGET}"
			"-DCOMPILER_RT_BUILD_LIBFUZZER=yes"
			"-DCOMPILER_RT_BUILD_SANITIZERS=yes"
		)
	fi
	cmake-utils_src_configure
}

src_install() {
	# There is install conflict between cross-armv7a-cros-linux-gnueabihf
	# and cross-armv7a-cros-linux-gnueabi. Remove this once we are ready to
	# move to cross-armv7a-cros-linux-gnueabihf.
	if [[ ${CTARGET} == armv7a-cros-linux-gnueabi ]] ; then
		return
	fi
	cmake-utils_src_install

	# includes and docs are installed for all sanitizers and xray
	# These files conflict with files provided in llvm ebuild
	local libdir=$(llvm-config --libdir)
	rm -rf "${ED}"/usr/share || die
	rm -rf "${ED}${libdir}"/clang/*/include || die
	rm -f "${ED}${libdir}"/clang/*/*list.txt || die
	rm -f "${ED}${libdir}"/clang/*/*/*list.txt || die
	rm -f "${ED}${libdir}"/clang/*/dfsan_abilist.txt || die
	rm -f "${ED}${libdir}"/clang/*/*/dfsan_abilist.txt || die
	rm -f "${ED}${libdir}"/clang/*/bin/* || die

	if is_baremetal_abi; then
		# Verify that no relocations are generated for baremetal.
		local elf_file
		while read -r elf_file; do
			$(tc-getREADELF) --relocs "${elf_file}" | grep GOT && \
				die "Unexpected GOT relocations found in ${elf_file}"
		done < <(scanelf -RByF '%F' "${D}")
	fi

	# Copy compiler-rt files to a new clang version to handle llvm updates gracefully.
	local llvm_version=$(llvm-config --version)
	local clang_full_version=${llvm_version%svn*}
	clang_full_version=${clang_full_version%git*}
	local major_version=${clang_full_version%%.*}
	local new_full_version="$((major_version + 1)).0.0"
	local old_full_version="$((major_version - 1)).0.0"
	local new_major_version="$((major_version + 1))"
	local old_major_version="$((major_version - 1))"
	# Upstream has moved to use major version instead of major.minor.sub format.
	# So copy installed files to both (major+/-1) and (major+/-1).0.0 dirs.
	local rt_install_path
	if [[ -d "${D}${libdir}/clang/${clang_full_version}" ]]; then
		rt_install_path="${D}${libdir}/clang/${clang_full_version}"
		# Copy files from /path/<num>.0.0 to /path/<num>.
		cp -r "${rt_install_path}" "${D}${libdir}/clang/${major_version}" || die
	elif [[ -d "${D}${libdir}/clang/${major_version}" ]]; then
		rt_install_path="${D}${libdir}/clang/${major_version}"
		# Copy files from /path/<num> to /path/<num>.0.0 .
		cp -r "${rt_install_path}" "${D}${libdir}/clang/${clang_full_version}" || die
	else
		die "Could not find installed compiler-rt files."
	fi
	cp -r "${rt_install_path}" "${D}${libdir}/clang/${new_full_version}" || die
	cp -r "${rt_install_path}" "${D}${libdir}/clang/${new_major_version}" || die
	cp -r "${rt_install_path}" "${D}${libdir}/clang/${old_full_version}" || die
	cp -r "${rt_install_path}" "${D}${libdir}/clang/${old_major_version}" || die
}
