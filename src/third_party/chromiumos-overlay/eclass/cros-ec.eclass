# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-ec.eclass
# @MAINTAINER:
# Chromium OS Firmware Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building Chromium OS EC firmware
# @DESCRIPTION:
# Builds the EC firmware and installs into /build/<board>/<EC_board> so that
# the signer can pick it up. Note that this doesn't install the firmware into
# the rootfs; that has to be done by a separate ebuild since the signer runs
# after the build.
#
# NOTE: When making changes to this class, make sure to modify all the -9999
# ebuilds that inherit it (e.g., chromeos-ec) to work around
# https://issuetracker.google.com/201299127.

if [[ -z "${_ECLASS_CROS_EC}" ]]; then
_ECLASS_CROS_EC="1"

# Check for EAPI 7+.
case "${EAPI:-0}" in
0|1|2|3|4|5|6) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
*) ;;
esac

inherit toolchain-funcs cros-ec-board cros-workon cros-unibuild coreboot-sdk

HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/ec/+/HEAD/README.md"

LICENSE="CrOS-EC"
IUSE="quiet verbose +coreboot-sdk unibuild fuzzer bootblock_in_ec asan msan ubsan test"
REQUIRED_USE="coreboot-sdk unibuild"

RDEPEND="
	fuzzer? (
		dev-libs/openssl:=
		dev-libs/protobuf:=
	)
	test? (
		dev-libs/openssl:=
		dev-libs/protobuf:=
	)
"

# EC build requires libftdi, but not used for runtime (b:129129436).
DEPEND="
	${RDEPEND}
	dev-embedded/libftdi:1=
	fuzzer? ( dev-libs/libprotobuf-mutator:= )
	test? ( dev-libs/libprotobuf-mutator:= )
	virtual/chromeos-ec-private-files
	virtual/chromeos-ec-touch-firmware
	bootblock_in_ec? ( sys-boot/coreboot )
"

# We don't want binchecks since we're cross-compiling firmware images using
# non-standard layout.
RESTRICT="binchecks"

# @FUNCTION: cros-ec_src_unpack
# @DESCRIPTION:
# Get source files.
cros-ec_src_unpack() {
	debug-print-function "${FUNCNAME[0]}" "$@"
	cros-workon_src_unpack
}

# @FUNCTION: cros-ec_src_prepare
# @DESCRIPTION: Set compilation to EC source directory and make sure private
# source files are in source directory (if private source is available).
cros-ec_src_prepare() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	default

	# We want compilation to happen in the EC source directory.
	S+="/platform/ec"

	# Link the private sources in the private/ sub-directory.
	ln -sfT "${SYSROOT}/firmware/ec-private" "${S}/private" || die
}

# @FUNCTION: cros-ec_set_build_env
# @DESCRIPTION:
# Set toolchain and build options.
cros-ec_set_build_env() {
	get_ec_boards

	cros_allow_gnu_build_tools

	# Let the EC Makefiles set the compiler. It already has logic for choosing
	# between gcc and clang for the different architectures that EC builds.
	unset CC

	# Setting SYSROOT to the board's sysroot (e.g., /build/hatch) causes
	# compilation failures when cross-compiling for other targets (e.g., ARM).
	# HOST_SYSROOT is used by the EC Makefiles to set the sysroot when building
	# for the host.
	export HOST_SYSROOT=${SYSROOT}
	unset SYSROOT

	# Let the EC Makefiles determine architecture flags. For example, using
	# "-march=goldmont" fails when using "armv7m-cros-eabi-clang" with the
	# error: the clang compiler does not support '-march=goldmont'
	filter-flags "-march=*"

	# b/247791129: EC expects HOST_PKG_CONFIG to be the pkg-config targeting the
	# platform that the EC is running on top of (e.g., the Chromebook's AP).
	# That platform corresponds to the ChromeOS "$BOARD" and the pkg-config for
	# the "$BOARD" being built is specified by tc-getPKG_CONFIG.
	export HOST_PKG_CONFIG
	HOST_PKG_CONFIG=$(tc-getPKG_CONFIG)

	# EC expects BUILD_PKG_CONFIG to be the pkg-config targeting the build
	# machine (the machine doing the compilation).
	export BUILD_PKG_CONFIG
	BUILD_PKG_CONFIG=$(tc-getBUILD_PKG_CONFIG)

	EC_OPTS=()
	use quiet && EC_OPTS+=( "-s V=0" )
	use verbose && EC_OPTS+=( "V=1" )

	# Disable the kconfig checker, as the platform/ec commit queue
	# does not use this code path.
	EC_OPTS+=( "ALLOW_CONFIG=1" )
}

# @FUNCTION: cros-ec_make_ec
# @INTERNAL
# @USAGE: <board name> <build directory> [path to touchpad firmware to be packed] [path to bootblock to be packed]
# @DESCRIPTION:
# Build EC with a supplied configuration and output directory.
cros-ec_make_ec() {
	local board="$1"
	local build_dir="$2"
	local touchpad_fw="$3"
	local bootblock="$4"
	local extra_opts=()

	einfo "Building EC for ${board} into ${build_dir} with" \
		"touchpad_fw=${touchpad_fw} bootblock=${bootblock}"
	einfo "pwd: $(pwd)"

	if [[ -n "${touchpad_fw}" ]]; then
		extra_opts+=( "TOUCHPAD_FW=${touchpad_fw}" )
	fi
	if [[ -n "${bootblock}" ]]; then
		extra_opts+=( "BOOTBLOCK=${bootblock}" )
	fi

	BOARD=${board} emake "${EC_OPTS[@]}" clean
	BOARD=${board} emake "${EC_OPTS[@]}" "${extra_opts[@]}" all
	# Since the ec codebase does not allow specifying a target build
	# directory, move its build directory to the requested location.
	rm -rf "${build_dir}"
	mv build "${build_dir}"
}

# @FUNCTION: cros-ec_src_compile
# @DESCRIPTION:
# Compile all boards specified in EC_BOARDS variable.
cros-ec_src_compile() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	cros-ec_set_build_env

	local target
	einfo "Building targets: ${EC_BOARDS[*]}"
	for target in "${EC_BOARDS[@]}"; do
		# Always pass TOUCHPAD_FW parameter: boards that do not require
		# it will simply ignore the parameter, even if the touchpad FW
		# file does not exist.
		local touchpad_fw="${HOST_SYSROOT}/firmware/${target}/touchpad.bin"

		# In certain devices, the only root-of-trust available is EC-RO.
		# Thus the AP bootblock needs to be installed in this write-protected
		# area, and supplied to AP on boot.  See b:110907438 for details.
		local bootblock
		local bootblock_serial
		local target_root
		target_root="${HOST_SYSROOT}/firmware/${target}"

		if use bootblock_in_ec; then
			bootblock="${target_root}/coreboot/bootblock.bin"
			bootblock_serial="${target_root}/coreboot_serial/bootblock.bin"

			if [[ -f "${bootblock_serial}" ]]; then
				# Since we are including AP bootblock, two sets
				# of EC images need to be built -- one with
				# serial console enabled, and one without.
				cros-ec_make_ec "${target}" \
					"${WORKDIR}/build_${target}_serial" \
					"${touchpad_fw}" "${bootblock_serial}"
			fi
		fi
		cros-ec_make_ec "${target}" "${WORKDIR}/build_${target}" \
			"${touchpad_fw}" "${bootblock}"
	done

	if use fuzzer; then
		local sanitizers=()
		use asan && sanitizers+=( "TEST_ASAN=y" )
		use msan && sanitizers+=( "TEST_MSAN=y" )
		use ubsan && sanitizers+=( "TEST_UBSAN=y" )
		emake buildfuzztests "${sanitizers[@]}"
	fi
}

# @FUNCTION: cros-ec_board_install
# @USAGE: <board name> <build directory> <output directory to install artifacts> [suffix to be used for installed artifacts]
# @DESCRIPTION:
# Install firmware binaries for a specific board.
# If suffix specified is "serial", then ec.bin => ec.serial.bin
cros-ec_board_install() {
	local board="$1"
	local build_dir="$2"
	local dest_dir="$3"
	local suffix="$4"
	local file_suffix
	local ecrw

	einfo "Installing EC for ${board} from ${build_dir} into ${dest_dir}" \
		"(suffix=${suffix})"

	if [[ -n "${suffix}" ]]; then
		file_suffix=".${suffix}"
	fi

	insinto "${dest_dir}"
	pushd "${build_dir}/${target}" >/dev/null || die

	openssl dgst -sha256 -binary RO/ec.RO.flat > RO/ec.RO.hash
	newins ec.bin "ec${file_suffix}.bin"
	newins ec.obj "ec${file_suffix}.obj"
	if grep -q '^CONFIG_VBOOT_EFS=y' .config; then
		# This extracts EC_RW.bin (= RW_A region image) from ec.bin.
		futility sign --type rwsig --ecrw_out EC_RW.bin ec.bin || die
		ecrw="EC_RW.bin"
	else
		ecrw="RW/ec.RW.flat"
	fi
	newins "${ecrw}" "ec${file_suffix}.RW.bin"
	openssl dgst -sha256 -binary "${ecrw}" > RW/ec.RW.hash
	newins RW/ec.RW.hash "ec${file_suffix}.RW.hash"
	# Intermediate file for debugging.
	newins RW/ec.RW.elf "ec${file_suffix}.RW.elf"

	# Install RW_B files except for RWSIG, which uses the same files as RW_A
	if grep -q '^CONFIG_RW_B=y' .config && \
			! grep -q '^CONFIG_RWSIG_TYPE_RWSIG=y' .config; then
		openssl dgst -sha256 -binary RW/ec.RW_B.flat > RW/ec.RW_B.hash
		newins RW/ec.RW_B.flat "ec${file_suffix}.RW_B.bin"
		newins RW/ec.RW_B.hash "ec${file_suffix}.RW_B.hash"
		# Intermediate file for debugging.
		newins RW/ec.RW_B.elf "ec${file_suffix}.RW_B.elf"
	fi

	if grep -q '^CONFIG_FW_INCLUDE_RO=y' .config; then
		newins RO/ec.RO.flat "ec${file_suffix}.RO.bin"
		newins RO/ec.RO.hash "ec${file_suffix}.RO.hash"
		# Intermediate file for debugging.
		newins RO/ec.RO.elf "ec${file_suffix}.RO.elf"
	fi

	# The shared objects library is not built by default.
	if grep -q '^CONFIG_SHAREDLIB=y' .config; then
		newins libsharedobjs/libsharedobjs.elf "libsharedobjs${file_suffix}.elf"
	fi

	if [[ -f chip/npcx/spiflashfw/npcx_monitor.bin ]]; then
		doins chip/npcx/spiflashfw/npcx_monitor.bin
	fi
	popd > /dev/null || die
}

# @FUNCTION: cros-ec_src_install
# @DESCRIPTION:
# Install all boards specified in EC_BOARDS into /firmware.
cros-ec_src_install() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	cros-ec_set_build_env

	local target

	einfo "Installing targets: ${EC_BOARDS[*]}"
	for target in "${EC_BOARDS[@]}"; do
		cros-ec_board_install "${target}" "${WORKDIR}/build_${target}" \
			"/firmware/${target}" "" \
			|| die "Couldn't install ${target}"
		if use bootblock_in_ec && \
			[[ -d "${WORKDIR}/build_${target}_serial" ]]; then
				cros-ec_board_install "${target}" "${WORKDIR}/build_${target}_serial" \
					"/firmware/${target}" serial \
					|| die "Couldn't install ${target} (serial)"
		fi
	done

	if use fuzzer; then
		local f

		insinto /usr/libexec/fuzzers
		exeinto /usr/libexec/fuzzers
		for f in build/host/*_fuzz/*_fuzz.exe; do
			local fuzzer="$(basename "${f}")"
			local custom_owners="${S}/fuzz/${fuzzer%exe}owners"
			fuzzer="ec_${fuzzer%_fuzz.exe}_fuzzer"
			newexe "${f}" "${fuzzer}"
			einfo "CUSTOM OWNERS = '${custom_owners}'"
			if [[ -f "${custom_owners}" ]]; then
				newins "${custom_owners}" "${fuzzer}.owners"
			else
				newins "${S}/OWNERS" "${fuzzer}.owners"
			fi
			local fuzzer_component_id="167114"
			echo "${fuzzer_component_id}" | newins - "${fuzzer}.components"
		done
	fi
}

EXPORT_FUNCTIONS src_unpack src_prepare src_compile src_install

fi  # _ECLASS_CROS_EC
