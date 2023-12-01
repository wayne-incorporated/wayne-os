# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

# @ECLASS: cros-llvm.eclass
# @MAINTAINER:
# ChromeOS toolchain team.<chromeos-toolchain@google.com>

# @DESCRIPTION:
# Functions to set the right toolchains and install prefix for llvm
# related libraries in crossdev stages.

inherit multilib

IUSE="continue-on-patch-failure"

BDEPEND="dev-python/dataclasses"
if [[ ${CATEGORY} == cross-* ]] ; then
	DEPEND="
		${CATEGORY}/binutils
		${CATEGORY}/gcc
		sys-devel/llvm
		"
fi

export CBUILD=${CBUILD:-${CHOST}}
export CTARGET=${CTARGET:-${CHOST}}

if [[ ${CTARGET} = ${CHOST} ]] ; then
	if [[ ${CATEGORY/cross-} != ${CATEGORY} ]] ; then
		export CTARGET=${CATEGORY/cross-}
	fi
fi

setup_cross_toolchain() {
	export CC="${CBUILD}-clang"
	export CXX="${CBUILD}-clang++"
	export PREFIX="/usr"

	if [[ ${CATEGORY} == cross-* ]] ; then
		export CC="${CTARGET}-clang"
		export CXX="${CTARGET}-clang++"
		export PREFIX="/usr/${CTARGET}/usr"
		export AS="$(tc-getAS ${CTARGET})"
		export STRIP="$(tc-getSTRIP ${CTARGET})"
		export OBJCOPY="$(tc-getOBJCOPY ${CTARGET})"
	elif [[ ${CTARGET} != ${CBUILD} ]] ; then
		export CC="${CTARGET}-clang"
		export CXX="${CTARGET}-clang++"
	fi
	unset ABI MULTILIB_ABIS DEFAULT_ABI
	multilib_env ${CTARGET}
}

prepare_patches() {
	local failure_mode
	failure_mode="$(usex continue-on-patch-failure continue fail)"
	"${FILESDIR}"/patch_manager/patch_manager.py \
		--svn_version "$(get_most_recent_revision)" \
		--patch_metadata_file "${FILESDIR}"/PATCHES.json \
		--failure_mode "${failure_mode}" \
		--src_path "${S}" || die
}

# shellcheck disable=SC2120
get_most_recent_revision() {
	local subdir="${1:-"${S}/llvm"}"
	# Tries to get the revision ID of the most recent commit
	local rev
	rev="$("${FILESDIR}"/patch_manager/git_llvm_rev.py --llvm_dir "${subdir}" --sha "$(git -C "${subdir}" rev-parse HEAD)")" || die "failed to get most recent llvm revision from ${subdir}"
	cut -d 'r' -f 2 <<< "${rev}"
}

is_baremetal_abi() {
	# ABIs like armv7m-cros-eabi or arm-none-eabi.
	if [[ "${CTARGET}" == *-eabi ]]; then
		return 0
	fi
	return 1
}
