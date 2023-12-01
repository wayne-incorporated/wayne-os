# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-arm64.eclass
# @BLURB: eclass for building arm64 binaries on arm
# @DESCRIPTION:
# Multilib builds are not supported in Chrome OS. A simple workaround for arm64
# builds on arm is to use the host toolchain. This eclass provides helper
# functions for arm64 environment setup, as well as integration with platform2
# packages. The "cros_arm64" USE flag determines whether a package should also
# build arm64 binaries on arm.

inherit cros-workon

IUSE="cros_arm64"

# Setup the build env to create 64bit objects.
# Force use of stdlibc++ in 64 mode (crbug.com/747696).
board_setup_64bit_au_env()
{
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"

	__AU_OLD_ARCH=${ARCH}
	__AU_OLD_ABI=${ABI}
	__AU_OLD_LIBDIR_arm64=${LIBDIR_arm64}
	__AU_OLD_CC=${CC}
	__AU_OLD_CXX=${CXX}
	export ARCH=arm64 ABI=arm64 LIBDIR_arm64="lib64"
	if [[ ${CC} == *"clang"* ]]; then
		export CC=aarch64-cros-linux-gnu-clang
		export CXX=aarch64-cros-linux-gnu-clang++
	fi
	__AU_OLD_SYSROOT=${SYSROOT}
	export LIBCHROME_SYSROOT=${SYSROOT}
	export SYSROOT=/usr/aarch64-cros-linux-gnu
	append-ldflags -L"${__AU_OLD_SYSROOT}"/usr/lib64 -L"${SYSROOT}"/usr/lib64
	append-cppflags -idirafter "${__AU_OLD_SYSROOT}"/usr/include
	# Link to libc and libstdc++ statically, because the arm64 shared
	# libraries are not available on arm. In addition, disable sanitizers
	# for 64-bit builds.
	append-flags -static -fno-sanitize=all
	append-ldflags -static -fno-sanitize=all
}

# undo what we did in the above function
board_teardown_64bit_au_env()
{
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"
	[ -z "${__AU_OLD_SYSROOT}" ] && \
		die "board_setup_64bit_au_env must be called first"

	filter-ldflags -L"${__AU_OLD_SYSROOT}"/usr/lib64 -L"${SYSROOT}"/usr/lib64
	filter-flags -idirafter "${__AU_OLD_SYSROOT}"/usr/include
	filter-flags -static -fno-sanitize=all
	export SYSROOT=${__AU_OLD_SYSROOT}
	export LIBDIR_arm64=${__AU_OLD_LIBDIR_arm64}
	export ABI=${__AU_OLD_ABI}
	export ARCH=${__AU_OLD_ARCH}
	if [[ ${CC} == *"clang"* ]]; then
		export CC=${__AU_OLD_CC}
		export CXX=${__AU_OLD_CXX}
	fi
	unset LIBCHROME_SYSROOT
}

# An ebuild inheriting from "cros-arm64" should also build arm64 binaries if this
# returns 0. The "arm" check allows the "cros_arm64" USE flag to be enabled for
# an overlay inherited by non-arm boards.
use_arm64() { use cros_arm64 && use arm; }

push_arm64_env() {
	board_setup_64bit_au_env
}

pop_arm64_env() {
	export CXX=${__AU_OLD_CXX}
	export CC=${__AU_OLD_CC}
	board_teardown_64bit_au_env
}

_get_arm64_cache() {
	echo "$(cros-workon_get_build_dir)/arm64"
}

platform_src_configure_arm64() {
	local cache=$(_get_arm64_cache)
	push_arm64_env
	cros-debug-add-NDEBUG
	append-lfs-flags
	platform_configure "--cache_dir=${cache}" "$@"
	pop_arm64_env
}

platform_src_compile_arm64() {
	local cache=$(_get_arm64_cache)
	push_arm64_env
	platform "compile" "--cache_dir=${cache}" "$@"
	pop_arm64_env
}

platform_out_arm64() {
	echo "$(_get_arm64_cache)/out/Default"
}
