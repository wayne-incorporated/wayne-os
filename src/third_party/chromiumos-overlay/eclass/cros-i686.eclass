# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-i686.eclass
# @BLURB: eclass for building i686 binaries on x86_64
# @DESCRIPTION:
# Multilib builds are not supported in Chrome OS. A simple workaround for i686
# builds on x86_64 is to use the host toolchain. This eclass provides helper
# functions for i686 environment setup, as well as integration with platform2
# packages. The "cros_i686" USE flag determines whether a package should also
# build i686 binaries on x86_64.

inherit cros-workon

IUSE="cros_i686"

# Setup the build env to create 32bit objects.
# Force use of stdlibc++ in 32 mode (crbug.com/747696).
board_setup_32bit_au_env()
{
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"

	__AU_OLD_ARCH=${ARCH}
	__AU_OLD_ABI=${ABI}
	__AU_OLD_LIBDIR_x86=${LIBDIR_x86}
	__AU_OLD_CC=${CC}
	__AU_OLD_CXX=${CXX}
	export ARCH=x86 ABI=x86 LIBDIR_x86="lib"
	__AU_OLD_CHOST=${CHOST}
	export CHOST=i686-cros-linux-gnu
	if [[ ${CC} == *"clang"* ]]; then
		export CC=${CHOST}-clang
		export CXX=${CHOST}-clang++
	fi
	__AU_OLD_SYSROOT=${SYSROOT}
	export LIBCHROME_SYSROOT=${SYSROOT}
	export SYSROOT=/usr/${CHOST}
	append-ldflags -L"${__AU_OLD_SYSROOT}"/usr/lib
	append-cppflags -idirafter "${__AU_OLD_SYSROOT}"/usr/include
	# Link to libc and libstdc++ statically, because the i686 shared
	# libraries are not available on x86_64. In addition, disable sanitizers
	# for 32-bit builds.
	append-flags -static -fno-sanitize=all
	append-ldflags -static -fno-sanitize=all
}

# undo what we did in the above function
board_teardown_32bit_au_env()
{
	[[ $# -eq 0 ]] || die "${FUNCNAME}: takes no arguments"
	[ -z "${__AU_OLD_SYSROOT}" ] && \
		die "board_setup_32bit_au_env must be called first"

	filter-ldflags -L"${__AU_OLD_SYSROOT}"/usr/lib
	filter-flags -idirafter "${__AU_OLD_SYSROOT}"/usr/include
	filter-flags -static -fno-sanitize=all
	export SYSROOT=${__AU_OLD_SYSROOT}
	export CHOST=${__AU_OLD_CHOST}
	export LIBDIR_x86=${__AU_OLD_LIBDIR_x86}
	export ABI=${__AU_OLD_ABI}
	export ARCH=${__AU_OLD_ARCH}
	if [[ ${CC} == *"clang"* ]]; then
		export CC=${__AU_OLD_CC}
		export CXX=${__AU_OLD_CXX}
	fi
	unset LIBCHROME_SYSROOT
}

# An ebuild inheriting from "cros-i686" should also build i686 binaries if this
# returns 0. The "amd64" check allows the "cros_i686" USE flag to be enabled for
# an overlay inherited by non-x86 boards.
use_i686() { use cros_i686 && use amd64; }

push_i686_env() {
	board_setup_32bit_au_env
}

pop_i686_env() {
	export CXX=${__AU_OLD_CXX}
	export CC=${__AU_OLD_CC}
	board_teardown_32bit_au_env
}

_get_i686_cache() {
	echo "$(cros-workon_get_build_dir)/i686"
}

platform_src_configure_i686() {
	local cache=$(_get_i686_cache)
	push_i686_env
	cros-debug-add-NDEBUG
	append-lfs-flags
	platform_configure "--cache_dir=${cache}" "$@"
	pop_i686_env
}

platform_src_compile_i686() {
	local cache=$(_get_i686_cache)
	push_i686_env
	platform "compile" "--cache_dir=${cache}" "$@"
	pop_i686_env
}

platform_out_i686() {
	echo "$(_get_i686_cache)/out/Default"
}
