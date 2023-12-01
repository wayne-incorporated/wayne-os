# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT=("6da7cc2ac34c6cb5cf5cbc35696e5f4fdfb618c6" "3107ce77310de08404a6300bd72274e4a4c65745" "1a5575a4ef4918b9b66506aa28edd8c2818cf4b4")
CROS_WORKON_TREE=("8b305500d7873478f74a3bf84f3e61900030c240" "4f46f18d58067b4d239004acd0ff8a285d0847ab" "53859a6033099ec15d83925bb70fbbc5ecbadc1d")
CROS_WORKON_PROJECT=(
	"chromiumos/platform/depthcharge"
	"chromiumos/platform/vboot_reference"
	"chromiumos/third_party/coreboot"
)

DESCRIPTION="coreboot's depthcharge payload"
HOMEPAGE="http://www.coreboot.org"
LICENSE="GPL-2"
KEYWORDS="*"
IUSE="fwconsole mocktpm pd_sync unibuild verbose debug
	physical_presence_power physical_presence_recovery test
	intel-compliance-test-mode"

# No pre-unibuild boards build firmware on ToT anymore.  Assume
# unibuild to keep ebuild clean.
REQUIRED_USE="unibuild"

DEPEND="
	sys-boot/coreboot:=
	chromeos-base/chromeos-ec-headers:=
	sys-boot/libpayload:=
	chromeos-base/chromeos-config:=
"

# While this package is never actually executed, we still need to specify
# RDEPEND. A binary version of this package could exist that was built using an
# outdated version of chromeos-config. Without the RDEPEND this stale binary
# package is considered valid by the package manager. This is problematic
# because we could have two binary packages installed having been build with
# different versions of chromeos-config. By specifying the RDEPEND we force
# the package manager to ensure the two versions use the same chromeos-config.
RDEPEND="${DEPEND}"

BDEPEND="
	dev-python/kconfiglib
	!test? (
		dev-util/cmake
		dev-util/cmocka
	)
"

CROS_WORKON_LOCALNAME=(
	"../platform/depthcharge"
	"../platform/vboot_reference"
	"../third_party/coreboot"
)
VBOOT_REFERENCE_DESTDIR="${S}/vboot_reference"
COREBOOT_DESTDIR="${S}/coreboot"
CROS_WORKON_DESTDIR=(
	"${S}/depthcharge"
	"${VBOOT_REFERENCE_DESTDIR}"
	"${COREBOOT_DESTDIR}"
)

CROS_WORKON_OPTIONAL_CHECKOUT=(
	""
	""
	"use test"
)

# Disable binary checks for PIE and relative relocatons.
# Don't strip to ease remote GDB use (cbfstool strips final binaries anyway).
# This is only okay because this ebuild only installs files into
# ${SYSROOT}/firmware, which is not copied to the final system image.
RESTRICT="binchecks strip"

# Disable warnings for executable stack.
QA_EXECSTACK="*"

inherit cros-workon cros-unibuild cros-sanitizers

# Build depthcharge with common options.
# Usage example: dc_make dev "${BUILD_DIR}" "${LIBPAYLOAD_DIR}"
# Args:
#   $1: Target to build
#   $2: Build directory to use.
#   $3: Directory where libpayload is located.
#   $4+: Any other Makefile arguments.
dc_make() {
	local target="$1"
	local builddir="$2"
	local libpayload="$3"

	shift 3

	local OPTS=(
		"EC_HEADERS=${SYSROOT}/usr/include/chromeos/ec"
		"LIBPAYLOAD_DIR=${libpayload}/libpayload"
		"obj=${builddir}"
	)

	use verbose && OPTS+=( "V=1" )
	use debug && OPTS+=( "SOURCE_DEBUG=1" )

	emake "${OPTS[@]}" \
		"${target}" \
		"$@"
}

# Build depthcharge for the current board.
# Builds the various output files for depthcharge:
#   depthcharge.elf   - normal image
#   dev.elf           - developer image
#   netboot.elf       - network image
# In addition, .map files are produced for each, and a .config file which
# holds the configuration that was used.
# Args
#   $1: board to build for.
#   $2: build directory
#   $3: libpayload dir
#   $4: recovery input method
#   $5: detachable ui enabled status ("True" for enabled)
make_depthcharge() {
	local board="$1"
	local builddir="$2"
	local libpayload="$3"
	local recovery_input="$4"
	local config_detachable="$5"
	local base_defconfig="board/${board}/defconfig"
	local defconfig="${T}/${board}-defconfig"
	local config="${builddir}/depthcharge.config"

	if [[ -e "${base_defconfig}" ]]; then
		cp "${base_defconfig}" "${defconfig}"
	else
		ewarn "${base_defconfig} does not exist!"
		touch "${defconfig}"
	fi

	chmod +w "${defconfig}"

	if use mocktpm ; then
		echo "CONFIG_MOCK_TPM=y" >> "${defconfig}"
	fi
	if use fwconsole || use intel-compliance-test-mode; then
		echo "CONFIG_CLI=y" >> "${defconfig}"
		echo "CONFIG_SYS_PROMPT=\"${board}: \"" >> "${defconfig}"
	fi

	if [[ "${config_detachable}" == "True" ]] ; then
		echo "CONFIG_DETACHABLE=y" >> "${defconfig}"
	fi

	if [[ -z "${recovery_input}" ]] ; then
		# TODO(b/229906790) Remove this once USE flag support not longer needed
		einfo "Recovery input method not found in config. Reverting to deprecated USE flags"
		if use physical_presence_power ; then
			die "physical_presence_power is not supported in firmware UI"
		elif use physical_presence_recovery ; then
			recovery_input="RECOVERY_BUTTON"
		else
			recovery_input="KEYBOARD"
		fi
	fi
	if [[ "${recovery_input}" == "KEYBOARD" ]] ; then
		# PHYSICAL_PRESENCE_KEYBOARD=y by default
		:
	elif [[ "${recovery_input}" == "RECOVERY_BUTTON" ]] ; then
		echo "CONFIG_PHYSICAL_PRESENCE_KEYBOARD=n" >> "${defconfig}"
	elif [[ "${recovery_input}" == "POWER_BUTTON" ]] ; then
		die "Recovery input POWER_BUTTON is not supported in firmware UI"
	else
		die "Unknown recovery_input ${recovery_input}"
	fi

	dc_make defconfig "${builddir}" "${libpayload}" \
		KBUILD_DEFCONFIG="${defconfig}" \
		DOTCONFIG="${config}"

	dc_make depthcharge "${builddir}" "${libpayload}" \
		DOTCONFIG="${config}"
	dc_make dev "${builddir}" "${libpayload}.gdb" \
		DOTCONFIG="${config}"
	dc_make netboot "${builddir}" "${libpayload}.gdb" \
		DOTCONFIG="${config}"
}

# Copy the fwconfig from libpayload to a path
# Args:
#    $1: libpayload dir
#    $2: depthcharge build directory
_copy_fwconfig() {
	local src="${1}/libpayload/include/static_fw_config.h"
	local dest="${2}/static_fw_config.h"

	if [[ -s "${src}" ]]; then
		cp "${src}" "${dest}"
		einfo "Copying ${src} into local tree"
	else
		ewarn "${src} does not exist"
	fi
}

src_configure() {
	sanitizers-setup-env
	default
}

src_compile() {
	local builddir
	local libpayload

	pushd depthcharge >/dev/null || \
		die "Failed to change into ${PWD}/depthcharge"

		local name
		local depthcharge

	while read -r name && read -r depthcharge; do
		libpayload="${SYSROOT}/firmware/${name}/libpayload"
		builddir="$(cros-workon_get_build_dir)/${depthcharge}"
		mkdir -p "${builddir}"

		_copy_fwconfig "${libpayload}" "${builddir}"

		recovery_input="$(cros_config_host get-firmware-recovery-input depthcharge "${depthcharge}")" || \
			die "Unable to determine recovery input for ${depthcharge}"
		config_detachable="$(cros_config_host get-key-value \
			/firmware/build-targets depthcharge "${depthcharge}" \
			/firmware detachable-ui --ignore-unset)" || \
			die "Unable to detachable ui config for ${depthcharge}"

		make_depthcharge "${depthcharge}" "${builddir}" "${libpayload}" "${recovery_input}" "${config_detachable}"
	done < <(cros_config_host get-firmware-build-combinations depthcharge)

	popd >/dev/null || die
}

do_install() {
	local board="$1"
	local builddir="$2"
	local dstdir="/firmware"

	if [[ -n "${build_target}" ]]; then
		dstdir+="/${build_target}"
		einfo "Installing depthcharge ${build_target} into ${dstdir}"
	fi
	insinto "${dstdir}"

	pushd "${builddir}" >/dev/null || \
		die "couldn't access ${builddir}/ directory"

	local files_to_copy=(
		depthcharge.config
		{netboot,depthcharge,dev}.elf{,.map}
	)

	insinto "${dstdir}/depthcharge"
	doins "${files_to_copy[@]}"

	popd >/dev/null || die
}

src_install() {
	local build_target
	local builddir

	for build_target in $(cros_config_host \
			get-firmware-build-targets depthcharge); do
		builddir="$(cros-workon_get_build_dir)/${build_target}"

		do_install "${build_target}" "${builddir}"
	done
}

make_unittests() {
	local builddir="$1"

	local OPTS=(
		"EC_HEADERS=${SYSROOT}/usr/include/chromeos/ec"
		"CB_SOURCE=${COREBOOT_DESTDIR}"
		"LP_SOURCE=${COREBOOT_DESTDIR}/payloads/libpayload"
		"VB_SOURCE=${VBOOT_REFERENCE_DESTDIR}"
		"obj=${builddir}"
		"HOSTCC=$(tc-getBUILD_CC)"
		"HOSTCXX=$(tc-getBUILD_CXX)"
		"HOSTAR=$(tc-getBUILD_AR)"
		"HOSTAS=$(tc-getBUILD_AS)"
		"OBJCOPY=$(tc-getBUILD_OBJCOPY)"
		"OBJDUMP=$(tc-getBUILD_OBJDUMP)"
	)

	use verbose && OPTS+=( "V=1" )
	emake "${OPTS[@]}" "unit-tests"
	emake "${OPTS[@]}" "test-screenshot"
}

src_test() {
	local builddir="$(cros-workon_get_build_dir)/depthcharge.tests"

	pushd depthcharge >/dev/null || \
		die "Failed to change into ${PWD}/depthcharge"

	mkdir -p "${builddir}"
	make_unittests "${builddir}"
}
