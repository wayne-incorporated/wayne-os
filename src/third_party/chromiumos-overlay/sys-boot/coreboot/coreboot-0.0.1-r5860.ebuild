# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Change this version number when any change is made to configs/files under
# coreboot and an auto-revbump is required.
# VERSION=REVBUMP-0.0.71

EAPI=7
CROS_WORKON_COMMIT=("1a5575a4ef4918b9b66506aa28edd8c2818cf4b4" "c161772f40b8dd9ad184e7bfa9f9fb371873fefd" "3107ce77310de08404a6300bd72274e4a4c65745" "b6cf2236359fefe0653c633bdb1ebb875e891387" "47bd8af8c600fed48ca62f7327f358306570ccc8" "ee319ae7bc59e88b60142f40a9ec1b46656de4db" "b7d5b2d6a6dd05874d86ee900ff441d261f9034c" "a091694ff8cf49c6d387d2d3a7909f59a0c0259b" "5ec392755dad0644817a72d1d9a379171012b89d")
CROS_WORKON_TREE=("53859a6033099ec15d83925bb70fbbc5ecbadc1d" "f4c75ef8f6f58be632ef788eff8c8a10e8722dfa" "4f46f18d58067b4d239004acd0ff8a285d0847ab" "d58fd89336bb56d04a8ca33e421a1161e6acf4dd" "64c1893bf69ecef6f5da88dfd140e96177ad3eb9" "45d22a8711f85c4310c0c2121d3dc8a72793d375" "c0433b88f972fa26dded401be022c1c026cd644e" "d4e76e6daa1655ec62ca351efd06645202e9c433" "7fde8d90acf565a4612bd2520116163ccb52dc1f")
CROS_WORKON_PROJECT=(
	"chromiumos/third_party/coreboot"
	"chromiumos/third_party/arm-trusted-firmware"
	"chromiumos/platform/vboot_reference"
	"chromiumos/third_party/coreboot/amd_blobs"
	"chromiumos/third_party/coreboot/blobs"
	"chromiumos/third_party/coreboot/intel-microcode"
	"chromiumos/third_party/cbootimage"
	"chromiumos/third_party/coreboot/libgfxinit"
	"chromiumos/third_party/coreboot/libhwbase"
)
CROS_WORKON_LOCALNAME=(
	"coreboot"
	"arm-trusted-firmware"
	"../platform/vboot_reference"
	"coreboot/3rdparty/amd_blobs"
	"coreboot/3rdparty/blobs"
	"coreboot/3rdparty/intel-microcode"
	"cbootimage"
	"coreboot/3rdparty/libgfxinit"
	"coreboot/3rdparty/libhwbase"
)
CROS_WORKON_DESTDIR=(
	"${S}"
	"${S}/3rdparty/arm-trusted-firmware"
	"${S}/3rdparty/vboot"
	"${S}/3rdparty/amd_blobs"
	"${S}/3rdparty/blobs"
	"${S}/3rdparty/intel-microcode"
	"${S}/util/nvidia/cbootimage"
	"${S}/3rdparty/libgfxinit"
	"${S}/3rdparty/libhwbase"
)

CROS_WORKON_EGIT_BRANCH=(
	"chromeos-2016.05"
	"master"
	"main"
	"chromeos"
	"master"
	"master"
	"master"
	"main"
	"main"
)

inherit cros-workon toolchain-funcs cros-unibuild coreboot-sdk cros-sanitizers

DESCRIPTION="coreboot firmware"
HOMEPAGE="http://www.coreboot.org"
LICENSE="GPL-2"
KEYWORDS="*"

# SOC
IUSE="amd_cpu intel_cpu"
# GSC
IUSE="${IUSE} mocktpm ti50_onboard"
# AMD chipsets
IUSE="${IUSE} chipset_cezanne chipset_mendocino chipset_stoneyridge"
# Debug
IUSE="${IUSE} fw_debug intel_debug intel-compliance-test-mode"
# Qualcomm ramdump
IUSE="${IUSE} qualcomm_ramdump"
# Logging
IUSE="${IUSE} quiet quiet-cb verbose"
# Flashrom Emulator
IUSE="${IUSE} em100-mode"
# Common libraries
IUSE="${IUSE} coreboot-sdk"
IUSE="${IUSE} fsp memmaps mma private_fsp_headers rmt vmx"
IUSE="${IUSE} +bmpblk unibuild"

# virtual/coreboot-private-files is deprecated. When adding a new board you
# should add the coreboot-private-files-{board/chipset} ebuilds into the private
# overlays, and avoid creating virtual packages.
# See b/178642474
IUSE="${IUSE} coreboot-private-files-board coreboot-private-files-chipset"
IUSE="${IUSE} +fsp_gop"

# FPDT - FSP performance data
IUSE="${IUSE} fsp_perf"

# No pre-unibuild boards build firmware on ToT anymore.  Assume
# unibuild to keep ebuild clean.
REQUIRED_USE="unibuild"
# Make sure we don't use SDK gcc anymore.
REQUIRED_USE+=" coreboot-sdk"

# Disable binary checks for PIE and relative relocatons.
# Don't strip to ease remote GDB use (cbfstool strips final binaries anyway).
# This is only okay because this ebuild only installs files into
# ${SYSROOT}/firmware, which is not copied to the final system image.
RESTRICT="binchecks strip"

# Disable warnings for executable stack.
QA_EXECSTACK="*"

DEPEND="
	coreboot-private-files-board? ( sys-boot/coreboot-private-files-board:= )
	coreboot-private-files-chipset? ( sys-boot/coreboot-private-files-chipset:= )
	virtual/coreboot-private-files
	bmpblk? ( sys-boot/chromeos-bmpblk:= )
	chipset_stoneyridge? ( sys-boot/amd-firmware:= )
	chipset_cezanne? ( sys-boot/amd-cezanne-fsp:= )
	chipset_mendocino? ( sys-boot/amd-mendocino-fsp:= )
	chromeos-base/chromeos-config:=
	"

# While this package is never actually executed, we still need to specify
# RDEPEND. A binary version of this package could exist that was built using an
# outdated version of chromeos-config. Without the RDEPEND this stale binary
# package is considered valid by the package manager. This is problematic
# because we could have two binary packages installed having been build with
# different versions of chromeos-config. By specifying the RDEPEND we force
# the package manager to ensure the two versions use the same chromeos-config.
RDEPEND="${DEPEND}
	!sys-boot/amd-picasso-fsp
	"

set_build_env() {
	local board="$1"

	CONFIG="$(cros-workon_get_build_dir)/${board}.config"
	CONFIG_SERIAL="$(cros-workon_get_build_dir)/${board}-serial.config"
	# Strip the .config suffix
	BUILD_DIR="${CONFIG%.config}"
	BUILD_DIR_SERIAL="${CONFIG_SERIAL%.config}"
}

# Create the coreboot configuration files for a particular board. This
# creates a standard config and a serial config.
# Args:
#   $1: board name
#   $2: libpayload build target (for config.baseboard files)
create_config() {
	local board="$1"
	local base_board="$2"

	touch "${CONFIG}"

	if use rmt; then
		echo "CONFIG_MRC_RMT=y" >> "${CONFIG}"
	fi
	if use vmx; then
		elog "   - enabling VMX"
		echo "CONFIG_ENABLE_VMX=y" >> "${CONFIG}"
	fi
	if use quiet-cb; then
		# Suppress console spew if requested.
		cat >> "${CONFIG}" <<EOF
CONFIG_DEFAULT_CONSOLE_LOGLEVEL=3
# CONFIG_DEFAULT_CONSOLE_LOGLEVEL_8 is not set
CONFIG_DEFAULT_CONSOLE_LOGLEVEL_3=y
EOF
	fi
	if use mocktpm; then
		echo "CONFIG_VBOOT_MOCK_SECDATA=y" >> "${CONFIG}"
	fi
	if use mma; then
		echo "CONFIG_MMA=y" >> "${CONFIG}"
	fi
	if use intel_debug; then
		echo "CONFIG_SOC_INTEL_DEBUG_CONSENT=y" >> "${CONFIG}"
	fi
	if use ti50_onboard; then
		echo "CONFIG_CBFS_VERIFICATION=y" >> "${CONFIG}"
	fi
	if use fw_debug; then
		echo "CONFIG_BUILDING_WITH_DEBUG_FSP=y" >> "${CONFIG}"
	fi
	if use intel-compliance-test-mode; then
		echo "CONFIG_SOC_INTEL_COMPLIANCE_TEST_MODE=y" >> "${CONFIG}"
	fi
	if use qualcomm_ramdump; then
		echo "CONFIG_QC_SDI_ENABLE=y" >> "${CONFIG}"
	fi
	local version=$("${CHROOT_SOURCE_ROOT}"/src/third_party/chromiumos-overlay/chromeos/config/chromeos_version.sh |grep "^[[:space:]]*CHROMEOS_VERSION_STRING=" |cut -d= -f2 | tr - _)
	{
		# disable coreboot's own EC firmware building mechanism
		echo "CONFIG_EC_GOOGLE_CHROMEEC_FIRMWARE_NONE=y"
		echo "CONFIG_EC_GOOGLE_CHROMEEC_PD_FIRMWARE_NONE=y"
		# enable common GBB flags for development
		echo "CONFIG_GBB_FLAG_DEV_SCREEN_SHORT_DELAY=y"
		echo "CONFIG_GBB_FLAG_DISABLE_FW_ROLLBACK_CHECK=y"
		echo "CONFIG_GBB_FLAG_FORCE_DEV_BOOT_USB=y"
		echo "CONFIG_GBB_FLAG_FORCE_DEV_SWITCH_ON=y"
		echo "CONFIG_VBOOT_FWID_VERSION=\".${version}\""
	} >> "${CONFIG}"
	if use em100-mode; then
		einfo "Enabling em100 mode via CONFIG_EM100 (slower SPI flash)"
		echo "CONFIG_EM100=y" >> "${CONFIG}"
	fi
	# Use FSP's GOP in favor of coreboot's Ada based Intel graphics init
	# which we don't include at this time. A no-op on non-FSP/GOP devices.
	if use fsp_gop; then
		echo "CONFIG_RUN_FSP_GOP=y" >> "${CONFIG}"
	fi

	if use fsp_perf; then
		echo "CONFIG_DISPLAY_FSP_TIMESTAMPS=y" >> "${CONFIG}"
	fi

	# Override the automatic options created above with board config.
	local board_config="${FILESDIR}/configs/config.${board}"
	local baseboard_config="${FILESDIR}/configs/config.baseboard.${base_board}"

	if [[ -s "${baseboard_config}" ]]; then
		cat "${baseboard_config}" >> "${CONFIG}"
		# Handle the case when "${CONFIG}" does not have a newline in the end.
		echo >> "${CONFIG}"
	fi

	if [[ -s "${board_config}" ]]; then
		cat "${board_config}" >> "${CONFIG}"
		# Handle the case when "${CONFIG}" does not have a newline in the end.
		echo >> "${CONFIG}"
	else
		ewarn "Could not find existing config for ${board}."
	fi

	# Override mainboard vendor if needed.
	if [[ -n "${SYSTEM_OEM}" ]]; then
		echo "CONFIG_MAINBOARD_VENDOR=\"${SYSTEM_OEM}\"" >> "${CONFIG}"
	fi
	if [[ -n "${SYSTEM_OEM_VENDOR_ID}" ]]; then
		echo "CONFIG_SUBSYSTEM_VENDOR_ID=${SYSTEM_OEM_VENDOR_ID}" >> "${CONFIG}"
	fi
	if [[ -n "${SYSTEM_OEM_DEVICE_ID}" ]]; then
		echo "CONFIG_SUBSYSTEM_DEVICE_ID=${SYSTEM_OEM_DEVICE_ID}" >> "${CONFIG}"
	fi
	if [[ -n "${SYSTEM_OEM_ACPI_ID}" ]]; then
		echo "CONFIG_ACPI_SUBSYSTEM_ID=\"${SYSTEM_OEM_ACPI_ID}\"" >> "${CONFIG}"
	fi

	if use private_fsp_headers; then
		local fspsocname=$(grep "CONFIG_FSP_M_FILE" "${CONFIG}" | cut -d '"' -f2 | cut -d '/' -f4)
		echo "CONFIG_FSP_HEADER_PATH=\"3rdparty/blobs/intel/${fspsocname}/fsp/PartialHeader/Include\"" >> "${CONFIG}"
	fi

	# Serial config
	cp "${CONFIG}" "${CONFIG_SERIAL}"
	local board_fwserial="${FILESDIR}/configs/fwserial.${board}"
	if [[ ! -f "${board_fwserial}" && -n "${base_board}" ]]; then
		board_fwserial="${FILESDIR}/configs/fwserial.${base_board}"
	fi

	cat "${FILESDIR}/configs/fwserial.default" >> "${CONFIG_SERIAL}" || die
	# Handle the case when "${CONFIG_SERIAL}" does not have a newline in the end.
	echo >> "${CONFIG_SERIAL}"
	if [[ -s "${board_fwserial}" ]]; then
		cat "${board_fwserial}" >> "${CONFIG_SERIAL}" || die
		# Handle the case when "${CONFIG_SERIAL}" does not have a newline in the end.
		echo >> "${CONFIG_SERIAL}"
	fi

	# Check that we're using coreboot-sdk
	if ! use coreboot-sdk; then
		die "Enable coreboot-sdk to build coreboot."
	fi
	if grep -q "^CONFIG_ANY_TOOLCHAIN=y" "${CONFIG}"; then
		die "Drop ANY_TOOLCHAIN from ${CONFIG}: we don't support it anymore."
	fi

	einfo "Configured ${CONFIG} for board ${board} in ${BUILD_DIR}"
}

src_prepare() {
	local froot="${SYSROOT}/firmware"
	local privdir="${SYSROOT}/firmware/coreboot-private"
	local file

	default

	export GENERIC_COMPILER_PREFIX="invalid"

	mkdir "$(cros-workon_get_build_dir)"

	if [[ -d "${privdir}" ]]; then
		while read -d $'\0' -r file; do
			rsync --recursive --links --executability \
				"${file}" ./ || die
		done < <(find "${privdir}" -maxdepth 1 -mindepth 1 -print0)
	fi

	cp -a "${FILESDIR}/3rdparty/"* 3rdparty

	local name
	local coreboot
	local libpayload
	while read -r name; do
		read -r coreboot
		read -r libpayload
		set_build_env "${coreboot}"
		create_config "${coreboot}" "${libpayload}"
	done < <(cros_config_host "get-firmware-build-combinations" \
		coreboot,libpayload || die)
}

add_fw_blob() {
	local rom="$1"
	local cbname="$2"
	local blob="$3"
	local cbhash="${cbname%.bin}.hash"
	local hash="${blob%.bin}.hash"

	cbfstool "${rom}" add -r FW_MAIN_A,FW_MAIN_B -t raw -c lzma \
		-f "${blob}" -n "${cbname}" || die
	cbfstool "${rom}" add -r FW_MAIN_A,FW_MAIN_B -t raw -c none \
		-f "${hash}" -n "${cbhash}" || die
}

# Build coreboot with a supplied configuration and output directory.
#   $1: Build directory to use (e.g. "build_serial")
#   $2: Config file to use (e.g. ".config_serial")
#   $3: Build target build (e.g. "pyro")
make_coreboot() {
	local builddir="$1"
	local config_fname="$2"

	rm -rf "${builddir}" .xcompile

	local CB_OPTS=(
		obj="${builddir}"
		DOTCONFIG="${config_fname}"
		HOSTCC="$(tc-getBUILD_CC)"
		HOSTCXX="$(tc-getBUILD_CXX)"
		HOSTPKGCONFIG="$(tc-getBUILD_PKG_CONFIG)"
	)
	use quiet && CB_OPTS+=( "V=0" )
	use verbose && CB_OPTS+=( "V=1" )
	use quiet && REDIR="/dev/null" || REDIR="/dev/stdout"

	# Configure and build coreboot.
	yes "" | emake oldconfig "${CB_OPTS[@]}" >${REDIR}
	emake "${CB_OPTS[@]}"

	# Expand FW_MAIN_* since we might add some files
	cbfstool "${builddir}/coreboot.rom" expand -r FW_MAIN_A,FW_MAIN_B

	# Modify firmware descriptor if building for the EM100 emulator on
	# Intel platforms.
	if use intel_cpu && use em100-mode; then
		einfo "Enabling em100 mode via ifdttool (slower SPI flash)"
		ifdtool --em100 "${builddir}/coreboot.rom" || die
		mv "${builddir}/coreboot.rom"{.new,} || die
	fi
}

# Add fw blobs to the coreboot.rom.
#   $1: Build directory to use (e.g. "build_serial")
#   $2: Build target build (e.g. "pyro")
add_fw_blobs() {
	local builddir="$1"
	local build_target="$2"
	local froot="${SYSROOT}/firmware/${build_target}"
	local fblobroot="${SYSROOT}/firmware"

	local blob
	local cbname
	# shellcheck disable=SC2154 # FW_BLOBS may be provided by overlays.
	for blob in ${FW_BLOBS}; do
		local blobfile="${fblobroot}/${blob}"

		# Use per-board blob if available
		if [[ -e "${froot}/${blob}" ]]; then
			blobfile="${froot}/${blob}"
		fi

		cbname=$(basename "${blob}")
		add_fw_blob "${builddir}/coreboot.rom" "${cbname}" \
			"${blobfile}" || die
	done

	if [[ -d "${froot}/cbfs" ]]; then
		die "something is still using ${froot}/cbfs, which is deprecated."
	fi
}

src_compile() {
	# Set KERNELREVISION (really coreboot revision) to the ebuild revision
	# number followed by a dot and the first seven characters of the git
	# hash. The name is confusing but consistent with the coreboot
	# Makefile.
	# shellcheck disable=SC2154 # VCSID is provided by cros-workon.eclass.
	local sha1v="${VCSID/*-/}"
	export KERNELREVISION=".${PV}.${sha1v:0:7}"

	if ! use coreboot-sdk; then
		tc-export CC
		# Export the known cross compilers so there isn't a reliance
		# on what the default profile is for exporting a compiler. The
		# reasoning is that the firmware may need more than one to build
		# and boot.
		export CROSS_COMPILE_x86="i686-pc-linux-gnu-"
		export CROSS_COMPILE_mipsel="mipsel-cros-linux-gnu-"
		export CROSS_COMPILE_arm64="aarch64-cros-linux-gnu-"
		export CROSS_COMPILE_arm="armv7a-cros-linux-gnu- armv7a-cros-linux-gnueabihf-"
	else
		export CROSS_COMPILE_x86=${COREBOOT_SDK_PREFIX_x86_32}
		export CROSS_COMPILE_mipsel=${COREBOOT_SDK_PREFIX_mips}
		export CROSS_COMPILE_arm64=${COREBOOT_SDK_PREFIX_arm64}
		export CROSS_COMPILE_arm=${COREBOOT_SDK_PREFIX_arm}

		export PATH="/opt/coreboot-sdk/bin:${PATH}"
	fi

	use verbose && elog "Toolchain:\n$(sh util/xcompile/xcompile)\n"

	while read -r name; do
		read -r coreboot

		set_build_env "${coreboot}"
		make_coreboot "${BUILD_DIR}" "${CONFIG}"
		add_fw_blobs "${BUILD_DIR}" "${coreboot}"

		# Build a second ROM with serial support for developers.
		make_coreboot "${BUILD_DIR_SERIAL}" "${CONFIG_SERIAL}"
		add_fw_blobs "${BUILD_DIR_SERIAL}" "${coreboot}"
	done < <(cros_config_host "get-firmware-build-combinations" coreboot || die)
}

# Install files into /firmware
# Args:
#   $1: The build combination name
#   $2: The coreboot build target
do_install() {
	local build_combination="$1"
	local build_target="$2"
	local dest_dir="/firmware"
	local mapfile

	if [[ -n "${build_target}" ]]; then
		dest_dir+="/${build_target}"
		einfo "Installing coreboot ${build_target} into ${dest_dir}"
	fi
	insinto "${dest_dir}"

	newins "${BUILD_DIR}/coreboot.rom" coreboot.rom
	newins "${BUILD_DIR_SERIAL}/coreboot.rom" coreboot.rom.serial

	OPROM=$( awk 'BEGIN{FS="\""} /CONFIG_VGA_BIOS_FILE=/ { print $2 }' \
		"${CONFIG}" )
	CBFSOPROM=pci$( awk 'BEGIN{FS="\""} /CONFIG_VGA_BIOS_ID=/ { print $2 }' \
		"${CONFIG}" ).rom
	FSP=$( awk 'BEGIN{FS="\""} /CONFIG_FSP_FILE=/ { print $2 }' \
		"${CONFIG}" )
	if [[ -n "${FSP}" ]]; then
		newins "${FSP}" fsp.bin
	fi
	# Save the psp_verstage binary for signing on AMD Fam17h platforms
	if [[ -e "${BUILD_DIR}/psp_verstage.bin" ]]; then
		newins "${BUILD_DIR}/psp_verstage.bin" psp_verstage.bin
	fi
	if [[ -n "${OPROM}" ]]; then
		newins "${OPROM}" "${CBFSOPROM}"
	fi
	if use memmaps; then
		for mapfile in "${BUILD_DIR}"/cbfs/fallback/*.map
		do
			doins "${mapfile}"
		done
	fi
	newins "${CONFIG}" coreboot.config
	newins "${CONFIG_SERIAL}" coreboot_serial.config

	# Keep binaries with debug symbols around for crash dump analysis
	if [[ -s "${BUILD_DIR}/bl31.elf" ]]; then
		newins "${BUILD_DIR}/bl31.elf" bl31.elf
		newins "${BUILD_DIR_SERIAL}/bl31.elf" bl31.serial.elf
	fi
	insinto "${dest_dir}"/coreboot
	doins "${BUILD_DIR}"/cbfs/fallback/*.debug
	nonfatal doins "${BUILD_DIR}"/cbfs/fallback/bootblock.bin
	insinto "${dest_dir}"/coreboot_serial
	doins "${BUILD_DIR_SERIAL}"/cbfs/fallback/*.debug
	nonfatal doins "${BUILD_DIR_SERIAL}"/cbfs/fallback/bootblock.bin

	# coreboot's static_fw_config.h is copied into libpayload include
	# directory.
	insinto "/firmware/${build_combination}/libpayload/libpayload/include"
	doins "${BUILD_DIR}/static_fw_config.h"
	einfo "Installed static_fw_config.h into libpayload include directory"
}

src_configure() {
	sanitizers-setup-env
	default
}

src_install() {
	while read -r name; do
		read -r coreboot

		set_build_env "${coreboot}"
		do_install "${name}" "${coreboot}"
	done < <(cros_config_host "get-firmware-build-combinations" coreboot || die)
}
