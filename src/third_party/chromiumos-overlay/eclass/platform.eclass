# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# @ECLASS: platform.eclass
# @MAINTAINER:
# ChromiumOS Build Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building Chromium package in src/platform2
# @DESCRIPTION:
# Packages in src/platform2 are in active development. We want builds to be
# incremental and fast. This centralized the logic needed for this.

# @ECLASS-VARIABLE: WANT_LIBCHROME
# @DESCRIPTION:
# Set to yes if the package needs libchrome.
: "${WANT_LIBCHROME:=yes}"

# @ECLASS-VARIABLE: WANT_LIBBRILLO
# @DESCRIPTION:
# Set to yes if the package needs libbrillo.
: "${WANT_LIBBRILLO:=${WANT_LIBCHROME}}"

# @ECLASS-VARIABLE: PLATFORM_SUBDIR
# @DESCRIPTION:
# Subdir in src/platform2 where the package is located.

# @ECLASS-VARIABLE: PLATFORM_NATIVE_TEST
# @DESCRIPTION:
# If set to yes, run the test only for amd64 and x86.
: "${PLATFORM_NATIVE_TEST:=no}"

# @ECLASS-VARIABLE: PLATFORM_HOST_DEV_TEST
# @DESCRIPTION:
# If set to yes, make the full host's /dev available.  This is needed for tests
# that interact with e.g. /dev/loop nodes.
: "${PLATFORM_HOST_DEV_TEST:=no}"

# @ECLASS-VARIABLE: PLATFORM_BUILD
# @DESCRIPTION:
# Indicates whether this is a platform build by setting a non-empty value.
: "${PLATFORM_BUILD:=1}"

# @ECLASS-VARIABLE: PLATFORM_ARC_BUILD
# @DESCRIPTION:
# Set to yes if the package is built by ARC toolchain.
: "${PLATFORM_ARC_BUILD:=no}"

# @ECLASS-VARIABLE: OUT
# @DESCRIPTION:
# Path where build artifacts will end up.  Exported from this eclass when
# platform_src_unpack is called; not intended to be set in ebuilds that inherit
# this eclass.

inherit cros-debug cros-fuzzer cros-sanitizers cros-workon flag-o-matic toolchain-funcs multiprocessing

# Define these so they can be appended to.
DEPEND=""
RDEPEND=""

[[ "${WANT_LIBCHROME}" == "yes" ]] && inherit libchrome

# Sanity check: libbrillo can't exist without libchrome.
if [[ "${WANT_LIBBRILLO}" == "yes" ]]; then
	if [[ "${WANT_LIBCHROME}" == "no" ]]; then
		die "libbrillo requires libchrome"
	fi
	# shellcheck disable=SC2154
	DEPEND+=" >=chromeos-base/libbrillo-0.0.1-r${REQUIRED_LIBBRILLO_EBUILD_VERSION}:="
	RDEPEND+=" >=chromeos-base/libbrillo-0.0.1-r${REQUIRED_LIBBRILLO_EBUILD_VERSION}:="
fi

# While not all packages utilize USE=test, it's common to write gn conditionals
# based on the flag.  Add it to the eclass so ebuilds don't have to duplicate it
# everywhere even if they otherwise aren't using the flag.
IUSE="compdb_only compilation_database cpp20 cros_host test"

# Similarly to above, we use gtest (includes gmock) for unittests in platform2
# packages. Add the dep all the time even if a few packages wouldn't use it as
# it doesn't add any real overhead. As we often use the FRIEND_TEST macro
# provided by gtest/gtest_prod.h in regular class definitions, the gtest
# dependency is needed outside test as well.
DEPEND+="
	cros_host? ( dev-util/gn )
	>=dev-cpp/gtest-1.10.0:=
"


# @FUNCTION: platform_gen_compilation_database
# @DESCRIPTION:
# Generates a compilation database for use by language servers.
platform_gen_compilation_database() {
	local db_chroot="${OUT}/compile_commands_chroot.json"

	ninja -C "${OUT}" -t compdb cc cxx > "${db_chroot}" || die

	# Make relative include paths absolute.
	sed -i -e "s:-I\./:-I${OUT}/:g" "${db_chroot}" || die

	local compdb_no_chroot="/mnt/host/source/chromite/ide_tooling/scripts/compdb_no_chroot.py"
	# shellcheck disable=SC2154
	< "${db_chroot}" \
	"${compdb_no_chroot}" "${EXTERNAL_TRUNK_PATH}" \
	> "${OUT}/compile_commands_no_chroot.json" || die

	echo \
"compile_commands_*.json are compilation databases for ${CATEGORY}/${PN}. The
files can be used by tools that support the commonly used JSON compilation
database format.

To use the compilation database with an IDE or other tools outside of the
chroot create a symlink named 'compile_commands.json' in the ${PN} source
directory (outside of the chroot) to compile_commands_no_chroot.json. Also
make sure that you have libc++ installed:

	$ sudo apt-get install libc++-dev
" > "${OUT}/compile_commands.txt" || die
}

platform() {
	local platform2_py="${PLATFORM_TOOLDIR}/platform2.py"
	local action="$1"
	shift

	local libdir="/usr/$(get_libdir)"
	local cache_dir="$(cros-workon_get_build_dir)"
	if [[ ${PLATFORM_ARC_BUILD} == "yes" ]]; then
		# shellcheck disable=SC2154
		export SYSROOT="${ARC_SYSROOT}"
		libdir="/vendor/$(get_libdir)"
		# shellcheck disable=SC2154
		cache_dir="${BUILD_DIR}"
	fi
	if [[ "${WANT_LIBCHROME}" == "yes" ]]; then
		export BASE_VER="$(libchrome_ver)"
	fi
	local cmd=(
		"${platform2_py}"
		--libdir="${libdir}"
		--use_flags="${USE}"
		--jobs="$(makeopts_jobs)"
		--action="${action}"
		--cache_dir="${cache_dir}"
		--platform_subdir="${PLATFORM_SUBDIR}"
		"$@"
	)
	if use cros_host; then
		cmd+=( --host )
	fi
	if [[ "${CROS_WORKON_INCREMENTAL_BUILD}" != "1" ]]; then
		cmd+=( --disable_incremental )
	fi
	"${cmd[@]}" || die
	# The stdout from this function used in platform_src_install
}

platform_is_native() {
	use amd64 || use x86
}

platform_src_unpack() {
	cros-workon_src_unpack
	if [[ ${#CROS_WORKON_DESTDIR[@]} -gt 1 || "${CROS_WORKON_OUTOFTREE_BUILD}" != "1" ]]; then
		S+="/platform2"
	fi
	PLATFORM_TOOLDIR="${S}/common-mk"
	S+="/${PLATFORM_SUBDIR}"
	export OUT="$(cros-workon_get_build_dir)/out/Default"
}

platform_test() {
	local platform2_test_py="${PLATFORM_TOOLDIR}/platform2_test.py"

	local action="$1"
	local bin="$2"
	local run_as_root="$3"
	local native_gtest_filter="$4"
	local qemu_gtest_filter="$5"

	local gtest_filter
	platform_is_native \
		&& gtest_filter=${native_gtest_filter} \
		|| gtest_filter=${qemu_gtest_filter:-${native_gtest_filter}}

	local cmd=(
		"${platform2_test_py}"
		--action="${action}"
		--sysroot="${SYSROOT}"
	)
	if use cros_host; then
		cmd+=( --host )
	fi
	if [[ "${PLATFORM_HOST_DEV_TEST}" == "yes" ]]; then
		cmd+=( --bind-mount-dev )
	fi
	if [[ "${run_as_root}" == "1" ]]; then
		cmd+=( --run_as_root )
	fi

	# Only add these options if they're specified ... leads to cleaner output
	# for developers to read.
	[[ -n ${gtest_filter} ]] && cmd+=( --gtest_filter="${gtest_filter}" )
	[[ -n ${P2_TEST_FILTER} ]] && cmd+=( --user_gtest_filter="${P2_TEST_FILTER}" )

	cmd+=(
		--
		"${bin}"
	)
	[[ -n "${P2_VMODULE}" ]] && cmd+=( --vmodule="${P2_VMODULE}" )
	echo "${cmd[@]}"
	"${cmd[@]}" || die
}

# @FUNCTION: platform_fuzzer_install
# @DESCRIPTION:
# Installs fuzzer targets in one common location for all fuzzing projects.
# @USAGE: <owners file> <fuzzer binary> [--dict dict_file] \
#	[--options options_file] [extra files ...]
platform_fuzzer_install() {
	fuzzer_install "$@"
}

# @FUNCTION: platform_fuzzer_test
# @DESCRIPTION:
# Tests a fuzzer binary (passed as an argument) against a small corpus of
# files. This is needed to make sure the fuzzer is built correctly and runs
# properly before being uploaded for contiguous tests.
# @USAGE: <fuzzer binary> [corpus_path]
platform_fuzzer_test() {
	fuzzer_test "$@" "${PLATFORM_TOOLDIR}"/fuzzer_corpus || die
}

platform_src_compile() {
	use compdb_only || platform "compile" "all"

	(use compilation_database || use compdb_only) && platform_gen_compilation_database
}

platform_configure() {
	platform "configure" "$@"
}

platform_src_configure() {
	cros-debug-add-NDEBUG
	append-lfs-flags
	sanitizers-setup-env
	if use test && use amd64 && platform_is_native && tc-is-cross-compiler; then
		# Do not use target specific flags when building for unit tests.
		# As the build machine may not support the generated instructions.
		# This only helps the code being rebuilt during unit tests, e.g.
		# libraries that are not rebuilt can still cause SIGILLs etc.
		append-flags '-march=corei7'
	fi
	platform_configure "$@"
}

platform_src_test() {
	# We pass SRC along so unittests can access data files in their checkout.
	# It's also the name used by the common.mk framework.
	export SRC="${S}"

	platform_test "pre_test"
	[[ "${PLATFORM_NATIVE_TEST}" == "yes" ]] && ! platform_is_native &&
		ewarn "Skipping unittests for non-x86: ${PN}" && return 0

	# Make sure this is available to platform2_test.py when run via platform2.py.
	export PLATFORM_HOST_DEV_TEST
	[[ "$(type -t platform_pkg_test)" == "function" ]] && platform_pkg_test
	platform_test "post_test"
}

platform_src_install() {
	local line
	while read -ra line; do
		echo "${line[@]}"
		eval "${line[@]}"
	done < <(platform install || die "platform install was failed.")

	use compilation_database && platform_install_compilation_database
}

platform_install_dbus_client_lib() {
	local libname=${1:-${PN}}

	local client_includes=/usr/include/${libname}-client
	local client_test_includes=/usr/include/${libname}-client-test

	# Install DBus proxy headers.
	insinto "${client_includes}/${libname}"
	doins "${OUT}/gen/include/${libname}/dbus-proxies.h"
	insinto "${client_test_includes}/${libname}"
	doins "${OUT}/gen/include/${libname}/dbus-proxy-mocks.h"

	if [[ -f "lib${libname}-client.pc.in" ]]; then
		# Install pkg-config for client libraries.
		ewarn "generate_pc_file.sh is deprecated.  Please switch to generate_pkg_config in BUILD.gn."
		"${PLATFORM_TOOLDIR}/generate_pc_file.sh" \
			"${OUT}" "lib${libname}-client" "${client_includes}" ||
			die "Error generating lib${libname}-client.pc file"
		"${PLATFORM_TOOLDIR}/generate_pc_file.sh" \
			"${OUT}" "lib${libname}-client-test" "${client_test_includes}" ||
			die "Error generating lib${libname}-client-test.pc file"
		insinto "/usr/$(get_libdir)/pkgconfig"
		doins "${OUT}/lib${libname}-client.pc"
		doins "${OUT}/lib${libname}-client-test.pc"
	fi
}

# @FUNCTION: platform_install_compilation_database
# @DESCRIPTION:
# Installs compilation database files to
# /build/compilation_database/${CATEGORY}/${PN}.
platform_install_compilation_database() {
	insinto "/build/compilation_database/${CATEGORY}/${PN}"

	doins "${OUT}/compile_commands.txt"
	doins "${OUT}/compile_commands_chroot.json"
	doins "${OUT}/compile_commands_no_chroot.json"
}

EXPORT_FUNCTIONS src_compile src_test src_configure src_unpack src_install
