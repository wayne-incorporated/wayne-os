# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Change this version number when any change is made to configs/files under
# libpayload and an auto-revbump is required.
# VERSION=REVBUMP-0.0.18

EAPI=7
CROS_WORKON_PROJECT=(
	"chromiumos/third_party/coreboot"
	"chromiumos/platform/vboot_reference"
)
CROS_WORKON_EGIT_BRANCH=(
	"chromeos-2016.05"
	"main"
)

DESCRIPTION="coreboot's libpayload library"
HOMEPAGE="http://www.coreboot.org"
LICENSE="GPL-2"
KEYWORDS="~*"
IUSE="coreboot-sdk unibuild verbose ti50_onboard"

# No pre-unibuild boards build firmware on ToT anymore.  Assume
# unibuild to keep ebuild clean.
REQUIRED_USE="unibuild"
# Make sure we don't use SDK gcc anymore.
REQUIRED_USE+=" coreboot-sdk"

DEPEND="chromeos-base/chromeos-config:="

# While this package is never actually executed, we still need to specify
# RDEPEND. A binary version of this package could exist that was built using an
# outdated version of chromeos-config. Without the RDEPEND this stale binary
# package is considered valid by the package manager. This is problematic
# because we could have two binary packages installed having been build with
# different versions of chromeos-config. By specifying the RDEPEND we force
# the package manager to ensure the two versions use the same chromeos-config.
RDEPEND="${DEPEND}"

CROS_WORKON_LOCALNAME=(
	"coreboot"
	"../platform/vboot_reference"
)

VBOOT_DESTDIR="${S}/3rdparty/vboot"
CROS_WORKON_DESTDIR=(
	"${S}"
	"${S}/3rdparty/vboot"
)

# commonlib, kconfig and xcompile are reused from coreboot.
# Everything else is not supposed to matter for
# libpayload.
CROS_WORKON_SUBTREE=(
	"payloads/libpayload src/commonlib util/kconfig util/xcompile"
	"Makefile firmware"
)

# Disable binary checks for PIE and relative relocatons.
# Don't strip to ease remote GDB use (cbfstool strips final binaries anyway).
# This is only okay because this ebuild only installs files into
# ${SYSROOT}/firmware, which is not copied to the final system image.
RESTRICT="binchecks strip"

# Disable warnings for executable stack.
QA_EXECSTACK="*"

inherit cros-workon toolchain-funcs coreboot-sdk cros-sanitizers

LIBPAYLOAD_BUILD_NAMES=()
LIBPAYLOAD_BUILD_TARGETS=()

src_unpack() {
	cros-workon_src_unpack
	S+="/payloads/libpayload"
}

src_configure() {
	sanitizers-setup-env

	local name
	local target

	export GENERIC_COMPILER_PREFIX="invalid"

	while read -r name && read -r target; do
		LIBPAYLOAD_BUILD_NAMES+=("${name}")
		LIBPAYLOAD_BUILD_TARGETS+=("${target}")
	done < <(cros_config_host get-firmware-build-combinations libpayload)

	for target in "${LIBPAYLOAD_BUILD_TARGETS[@]}"; do
		if [[ ! -s "${FILESDIR}/configs/config.${target}" ]]; then
			die "libpayload config does not exist for ${target}"
		fi
	done
}

# build libpayload for a certain config
#   $1: path to the dotconfig
#   $2: path to the build directory
libpayload_compile() {
	local dotconfig="$(realpath "$1")"
	local objdir="$(realpath "$2")"
	local OPTS=(
		obj="${objdir}"
		DOTCONFIG="${dotconfig}"
		HOSTCC="$(tc-getBUILD_CC)"
		HOSTCXX="$(tc-getBUILD_CXX)"
		VBOOT_SOURCE="${VBOOT_DESTDIR}"
	)
	use verbose && OPTS+=( "V=1" )

	yes "" | emake "${OPTS[@]}" oldconfig
	emake "${OPTS[@]}"
}

src_compile() {
	if ! use coreboot-sdk; then
		tc-getCC
		# Export the known cross compilers so there isn't a reliance
		# on what the default profile is for exporting a compiler. The
		# reasoning is that the firmware may need more than one to build
		# and boot.
		export CROSS_COMPILE_i386="i686-pc-linux-gnu-"
		# For coreboot.org upstream architecture naming.
		export CROSS_COMPILE_x86="i686-pc-linux-gnu-"
		export CROSS_COMPILE_mipsel="mipsel-cros-linux-gnu-"
		export CROSS_COMPILE_arm64="aarch64-cros-linux-gnu-"
		export CROSS_COMPILE_arm="armv7a-cros-linux-gnu- armv7a-cros-linux-gnueabihf-"
	else
		export CROSS_COMPILE_x86=${COREBOOT_SDK_PREFIX_x86_32}
		export CROSS_COMPILE_mipsel=${COREBOOT_SDK_PREFIX_mips}
		export CROSS_COMPILE_arm64=${COREBOOT_SDK_PREFIX_arm64}
		export CROSS_COMPILE_arm=${COREBOOT_SDK_PREFIX_arm}
	fi

	# we have all kinds of userland-cruft in CFLAGS that has no place in firmware.
	# coreboot ignores CFLAGS, libpayload doesn't, so prune it.
	unset CFLAGS

	local unique_targets=()
	readarray -t unique_targets \
		< <(printf "%s\n" "${LIBPAYLOAD_BUILD_TARGETS[@]}" | sort -u)

	local target
	local board_config
	local dotconfig
	local dotconfig_gdb
	for target in "${unique_targets[@]}"; do
		board_config="${FILESDIR}/configs/config.${target}"

		dotconfig="${T}/config.${target}"
		if use ti50_onboard; then
			echo "CONFIG_LP_CBFS_VERIFICATION=y" >> "${dotconfig}"
		fi
		cat "${board_config}" >> "${dotconfig}"
		# In case "${board_config}" does not have a newline at the end
		echo >> "${dotconfig}"
		libpayload_compile "${dotconfig}" "${T}/${target}"

		# Build a second set of libraries with GDB support for developers
		dotconfig_gdb="${T}/config_gdb.${target}"
		cp "${dotconfig}" "${dotconfig_gdb}"
		echo "CONFIG_LP_REMOTEGDB=y" >> "${dotconfig_gdb}"
		libpayload_compile "${dotconfig_gdb}" "${T}/${target}.gdb"
	done
}

src_install() {
	local i
	local name
	local target

	for i in "${!LIBPAYLOAD_BUILD_TARGETS[@]}"; do
		name="${LIBPAYLOAD_BUILD_NAMES[${i}]}"
		target="${LIBPAYLOAD_BUILD_TARGETS[${i}]}"

		emake obj="${T}/${target}" \
			DOTCONFIG="${T}/config.${target}" VBOOT_SOURCE="${VBOOT_DESTDIR}" \
			DESTDIR="${D}/firmware/${name}/libpayload" install
		emake obj="${T}/${target}.gdb" \
			DOTCONFIG="${T}/config_gdb.${target}" \
			VBOOT_SOURCE="${VBOOT_DESTDIR}" \
			DESTDIR="${D}/firmware/${name}/libpayload.gdb" install
	done
}
