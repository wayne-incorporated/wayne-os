# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-debug cros-unibuild cros-workon eutils

DESCRIPTION="ChromeOS firmware image builder"
HOMEPAGE="http://www.chromium.org"
LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~*"
IUSE="wilco_ec zephyr_ec"
IUSE="${IUSE} fsp unibuild u-boot tianocore cros_ec pd_sync +bmpblk"

# 'ec_ro_sync' can be a solution for devices that will fail to complete recovery
# due to TCPC reset (crbug.com/782427#c4), but may not work for every devices
# (crbug.com/1024401, and MT8183 family). Please double check before turning on
# this option.
IUSE="${IUSE} ec_ro_sync"
IUSE="${IUSE} +depthcharge"
IUSE="${IUSE} payload-align-64 +payload-compress-lzma payload-compress-lz4"
IUSE="${IUSE} +include_altfw"

# SOC
IUSE="${IUSE} intel_cpu"

REQUIRED_USE="^^ ( payload-compress-lzma payload-compress-lz4 )"


# No pre-unibuild boards build firmware on ToT anymore.  Assume
# unibuild to keep ebuild clean.
REQUIRED_USE="unibuild"

BDEPEND="chromeos-base/vboot_reference"

DEPEND="
	sys-boot/coreboot:=
	depthcharge? ( sys-boot/depthcharge:= )
	bmpblk? ( sys-boot/chromeos-bmpblk:= )
	tianocore? ( sys-boot/edk2:= )
	chromeos-base/chromeos-config:=
	u-boot? ( sys-boot/u-boot:= )
	cros_ec? ( chromeos-base/chromeos-ec:= )
	zephyr_ec? ( chromeos-base/chromeos-zephyr:= )
	pd_sync? ( chromeos-base/chromeos-ec:= )
	"

# While this package is never actually executed, we still need to specify
# RDEPEND. A binary version of this package could exist that was built using an
# outdated version of chromeos-config. Without the RDEPEND this stale binary
# package is considered valid by the package manager. This is problematic
# because we could have two binary packages installed having been build with
# different versions of chromeos-config. By specifying the RDEPEND we force
# the package manager to ensure the two versions use the same chromeos-config.
RDEPEND="${DEPEND}"

# Directory where the generated files are looked for and placed.
CROS_FIRMWARE_IMAGE_DIR="/firmware"
CROS_FIRMWARE_ROOT="${SYSROOT}${CROS_FIRMWARE_IMAGE_DIR}"

do_cbfstool() {
	einfo cbfstool "$@"
	cbfstool "$@" 2>&1 || die "Failed cbfstool invocation: cbfstool $*"
}

do_futility() {
	einfo futility "$@"
	futility "$@" 2>&1 || die "Failed futility invocation: futility $*"
}

sign_image() {
	local fw_image=$1
	local keydir=$2

	do_futility sign \
		--keyset "${keydir}" \
		--version 1 \
		--flags 0 \
		"${fw_image}"
}

add_payloads() {
	local fw_image=$1
	local ro_payload=$2
	local rw_payload=$3

	local -a args=(-n fallback/payload)

	if use payload-compress-lzma; then
		args+=(-c lzma)
	elif use payload-compress-lz4; then
		args+=(-c lz4)
	fi

	if use payload-align-64; then
		args+=(-a 64)
	fi

	if [ -n "${ro_payload}" ]; then
		do_cbfstool "${fw_image}" add-payload \
			-f "${ro_payload}" "${args[@]}"
	fi

	if [ -n "${rw_payload}" ]; then
		do_cbfstool "${fw_image}" add-payload -f "${rw_payload}" \
			"${args[@]}" -r FW_MAIN_A,FW_MAIN_B
	fi
}

# Returns true if EC supports EFS.
is_ec_efs_enabled() {
	local depthcharge_config="$1"

	grep -q "^CONFIG_EC_EFS=y$" "${depthcharge_config}"
}

# Returns true if coreboot is set up to perform EC software sync
is_early_ec_sync_enabled() {
	local coreboot_config="$1"

	grep -q "^CONFIG_VBOOT_EARLY_EC_SYNC=y$" "${coreboot_config}"
}

# Adds EC{ro,rw} images to CBFS
add_ec() {
	local depthcharge_config="$1"
	local coreboot_config="$2"
	local rom="$3"
	local name="$4"
	local ecroot="$5"
	local pad="0"
	local comp_type="lzma"

	# The initial implementation of EC software sync in coreboot does
	# not support decompression of the EC firmware images.  There is
	# not enough CAR/SRAM space available to store the entire image
	# decompressed, so it would have to be decompressed in a "streaming"
	# fashion.  See crbug.com/1023830.
	if [[ "${name}" != "pd" ]] && is_early_ec_sync_enabled "${coreboot_config}"; then
		einfo "Adding uncompressed EC image"
		comp_type="none"
	fi

	# When EFS is enabled, the payloads here may be resigned and enlarged so
	# extra padding is needed.
	if use depthcharge; then
		is_ec_efs_enabled "${depthcharge_config}" && pad="128"
	fi
	einfo "Padding ${name}{ro,rw} ${pad} byte."

	local rw_file="${ecroot}/ec.RW.bin"
	if [[ ! -f "${rw_file}" ]]; then
		if [[ -f "${ecroot}/ec.bin" ]]; then
			( cd "${T}" && dump_fmap -x "${ecroot}/ec.bin" RW_FW ) || \
				die "Unable to extract RW region from FMAP"
			rw_file="${T}/RW_FW"
		fi
	fi
	openssl dgst -sha256 -binary "${rw_file}" > "${T}/ecrw.hash" || \
		die "Unable to compute RW hash"

	do_cbfstool "${rom}" add -r FW_MAIN_A,FW_MAIN_B -t raw -c "${comp_type}" \
		-f "${rw_file}" -n "${name}rw" -p "${pad}"
	do_cbfstool "${rom}" add -r FW_MAIN_A,FW_MAIN_B -t raw -c none \
		-f "${T}/ecrw.hash" -n "${name}rw.hash"

	if ! use ec_ro_sync; then
		einfo "Skip packing EC RO."
	elif [[ -f "${ecroot}/ec.RO.bin" ]]; then
		do_cbfstool "${rom}" add -r COREBOOT -t raw -c "${comp_type}" \
			-f "${ecroot}/ec.RO.bin" -n "${name}ro" -p "${pad}"
		do_cbfstool "${rom}" add -r COREBOOT -t raw -c none \
			-f "${ecroot}/ec.RO.hash" -n "${name}ro.hash"
	else
		ewarn "Missing ${ecroot}/ec.RO.bin, skip packing EC RO."
	fi

	# Add EC version file for Wilco EC
	if use wilco_ec; then
		do_cbfstool "${rom}" add -r FW_MAIN_A,FW_MAIN_B -t raw -c none \
			-f "${ecroot}/ec.RW.version" -n "${name}rw.version"
	fi
}

# Add payloads and sign the image.
# This takes the base image and creates a new signed one with the given
# payloads added to it.
# The image is placed in directory ${outdir} ("" for current directory).
# An image suffix is added is ${suffix} is non-empty (e.g. "dev", "net").
# Args:
#   $1: Image type (e,g. "" for standard image, "dev" for dev image)
#   $2: Source image to start from.
#   $3: Payload to add to read-only image portion
#   $4: Payload to add to read-write image portion
build_image() {
	local image_type=$1
	local src_image=$2
	local ro_payload=$3
	local rw_payload=$4
	local devkeys_dir="${BROOT}/usr/share/vboot/devkeys"

	[ -n "${image_type}" ] && image_type=".${image_type}"
	local dst_image="${outdir}image${suffix}${image_type}.bin"

	einfo "Building image ${dst_image}"
	cp "${src_image}" "${dst_image}" || die
	add_payloads "${dst_image}" "${ro_payload}" "${rw_payload}"
	sign_image "${dst_image}" "${devkeys_dir}"
}

# Hash the payload of an altfw alternative bootloader
# Loads the payload from $rom on RW_LEGACY under:
#   altfw/<name>
# Stores the hash into $rom on RW-A and RW-B as:
#   altfw/<name>.sha256
# Args:
#   $1: rom file where the payload can be found
#   $2: name of the alternative bootloader
hash_altfw_payload() {
	local rom="$1"
	local name="$2"
	local payload_file="altfw/${name}"
	local hash_file="${payload_file}.sha256"
	local tmpfile="$(mktemp)"
	local tmphash="$(mktemp)"
	local rom

	einfo "  Hashing ${payload_file}"

	# Grab the raw uncompressed payload (-U) and hash it into $tmphash.
	do_cbfstool "${rom}" extract -r RW_LEGACY -n "${payload_file}" \
		-f "${tmpfile}" -U >/dev/null
	openssl dgst -sha256 -binary "${tmpfile}" > "${tmphash}"

	# Copy $tmphash into RW-A and RW-B.
	do_cbfstool "${rom}" add -r FW_MAIN_A,FW_MAIN_B \
		-f "${tmphash}" -n "${hash_file}" -t raw
}

# Set up alternative bootloaders
#
# This creates a new CBFS in the RW_LEGACY area and puts bootloaders into it,
# based on USE flags. A list is written to an "altfw/list" file so that there
# is a record of what is available.
# Args:
#   $1: coreboot build target to use for prefix on target-specific payloads
#   $2: coreboot file to add alternative bootloaders to
setup_altfw() {
	local rom="$2"
	local bl_list="${T}/altfw"

	einfo "Adding alternative firmware"

	# Add master header to the RW_LEGACY section
	printf "ptr_" > "${T}/ptr"
	do_cbfstool "${rom}" add -r RW_LEGACY -f "${T}/ptr" -n "header pointer" \
		-t "cbfs header" -b -4
	do_cbfstool "${rom}" add-master-header -r RW_LEGACY
	rm "${T}/ptr"
	: > "${bl_list}"

	# Add U-Boot if enabled
	if use u-boot; then
		einfo "- Adding U-Boot"

		do_cbfstool "${rom}" add-flat-binary -r RW_LEGACY -n altfw/u-boot \
			-c lzma -l 0x1110000 -e 0x1110000 \
			-f "${CROS_FIRMWARE_ROOT}/u-boot.bin"
		hash_altfw_payload "${rom}" u-boot
		echo "1;altfw/u-boot;U-Boot;U-Boot bootloader" >> "${bl_list}"
	fi

	# Add TianoCore if enabled
	if use tianocore; then
		einfo "- Adding TianoCore"

		# Some boards only have 1MB of RW_LEGACY space but UEFI is over
		# 800KB. Allow this to fail, in which case we just don't add it.
		if cbfstool "${rom}" add-payload -r RW_LEGACY \
				-n altfw/tianocore -c lzma -f \
				"${CROS_FIRMWARE_ROOT}/tianocore/UEFIPAYLOAD.fd"; then
			hash_altfw_payload "${rom}" tianocore
			echo "2;altfw/tianocore;TianoCore;TianoCore bootloader" \
				>> "${bl_list}"

			# For now, use TianoCore as the default.
			echo "0;altfw/tianocore;TianoCore;TianoCore bootloader" \
				>> "${bl_list}"
			einfo "  (sing TianoCore as default)"
		else
			ewarn "Not enough space for TianoCore: omitted"
		fi
	fi

	# Add the list
	einfo "- adding firmware list"
	do_cbfstool "${rom}" add -r RW_LEGACY -n altfw/list -t raw -f "${bl_list}"

	# Add the tag for silent updating.
	do_cbfstool "${rom}" add-int -r RW_LEGACY -i 1 -n "cros_allow_auto_update"

	# TODO(kitching): Get hash and sign.
}

# Check whether assets will fit in the image.
#
# Estimate the total size of compressed assets, uncompressed assets, and the
# compressed payload.  Warn when the size exceeds free space available in
# RO or RW CBFS regions.  Note that this is purely informational and doesn't
# actually trigger failure.
#
# Args:
#   $1: Filename of image to add to (use serial image for best coverage)
#   $2: Payload to add to both RO and RW regions
check_assets() {
	local rom="$1"
	local payload="$2"

	# The objcopy architecture doesn't really need to match, it just needs any ELF.
	local payload_size=$(objcopy -I elf32-i386 -O binary "${payload}" /proc/self/fd/1 2>/dev/null | xz -9 -c | wc -c)

	local rw_assets_size=$(find compressed-assets-rw "compressed-assets-rw/${build_name}" "raw-assets-rw/${build_name}" -maxdepth 1 -type f -print0 | du --files0-from=- -bc | tail -n1 | cut -f1)
	local rw_override_assets_size=$(find compressed-assets-rw-override "compressed-assets-rw-override/${build_name}" -maxdepth 1 -type f -print0 | du --files0-from=- -bc | tail -n1 | cut -f1)
	local rw_size=$((rw_assets_size + rw_override_assets_size + payload_size))
	local rw_free=$(($(do_cbfstool "${rom}" print -r FW_MAIN_A | awk '$1 ~ /empty/ {s+=$4} END {print s}') - payload_size))

	# Most RW assets are also added to RO region.
	local ro_assets_size=$(find compressed-assets-ro "compressed-assets-ro/${build_name}" -maxdepth 1 -type f -print0 | du --files0-from=- -bc | tail -n1 | cut -f1)
	local ro_size=$((ro_assets_size + rw_assets_size + payload_size))
	local ro_free=$(($(do_cbfstool "${rom}" print -r COREBOOT | awk '$1 ~ /empty/ {s+=$4} END {print s}') - payload_size))

	einfo "assets (RO): $((ro_size / 1024)) KiB ($((ro_free / 1024)) KiB free) ${build_name}"
	[[ ${ro_size} -gt ${ro_free} ]] &&
		ewarn "WARNING: RO estimated $(((ro_size - ro_free) / 1024)) KiB over limit ${build_name}"

	einfo "assets (RW): $((rw_size / 1024)) KiB ($((rw_free / 1024)) KiB free) ${build_name}"
	[[ ${rw_size} -gt ${rw_free} ]] &&
		ewarn "WARNING: RW estimated $(((rw_size - rw_free) / 1024)) KiB over limit ${build_name}"
}

# Add compressed assets, both common and target, to CBFS using cbfstool
# Args:
#  $1: Path where the compressed assets are present.
#  $2: CBFS Regions to add the compressed assets to.
add_compressed_assets() {
	local asset_path="$1"
	local cbfs_regions="$2"
	local build_name="$3"

	while IFS= read -r -d '' file; do
		do_cbfstool "${rom}" add -r "${cbfs_regions}" -f "${file}" \
			-n "$(basename "${file}")" -t raw -c precompression
	done < <(find "${asset_path}" -maxdepth 1 -type f -print0 | sort -z)

	# Pre uni-builds have build_name not set. So check to avoid adding
	# duplicate assets.
	if [ -n "${build_name}" ]; then
		while IFS= read -r -d '' file; do
			do_cbfstool "${rom}" add -r "${cbfs_regions}" -f "${file}" \
				-n "$(basename "${file}")" -t raw -c precompression
		done < <(find "${asset_path}/${build_name}" -maxdepth 1 -type f -print0 \
				| sort -z)
	fi
}

# Add Chrome OS assets to the base and serial images:
#       compressed-assets-ro/*
#         - fonts, images and screens for recovery mode, originally from
#           cbfs-ro-compress/*; pre-compressed in src_compile()
#       compressed-assets-rw/*
#         - files originally from cbfs-rw-compress/*; pre-compressed
#           in src_compile(); used for vbt*.bin
#       compressed-assets-rw-override/*
#         - updated images for screens, originally from
#           cbfs-rw-compress-override/*; pre-compressed in src_compile(); used
#           for rw_locale*.bin
#       raw-assets-rw/*
#         - files originally from cbfs-rw-raw/*, used for extra wifi_sar files
#
# Args:
#  $1: Filename of image to add to
add_assets() {
	local rom="$1"

	add_compressed_assets "compressed-assets-ro" "COREBOOT" "${build_name}"
	add_compressed_assets "compressed-assets-rw" \
				"COREBOOT,FW_MAIN_A,FW_MAIN_B" "${build_name}"
	add_compressed_assets "compressed-assets-rw-override" \
				"FW_MAIN_A,FW_MAIN_B" "${build_name}"

	while IFS= read -r -d '' file; do
		do_cbfstool "${rom}" add -r COREBOOT,FW_MAIN_A,FW_MAIN_B \
			-f "${file}" -n "$(basename "${file}")" -t raw
	done < <(find "raw-assets-rw/${build_name}" -type f -print0 | sort -z)
}

# Compress static and firmware target specific assets:
#       compressed-assets-ro/*
#         - fonts, images and screens for recovery mode, originally from
#           cbfs-ro-compress/*; pre-compressed in src_compile()
#       compressed-assets-rw/*
#         - files originally from cbfs-rw-compress/*; pre-compressed
#           in src_compile(); used for vbt*.bin
#       compressed-assets-rw-override/*
#         - updated images for screens, originally from
#           cbfs-rw-compress-override/*; pre-compressed in src_compile(); used
#           for rw_locale*.bin
# Args:
#  $1: Root path for the firmware build
#  $2: Firmware target where the uncompressed assets are present. When nothing
#      is passed, then static assets are being compressed.
compress_assets() {
	local froot="$1"
	local build_name="$2"

	# files from cbfs-ro-compress/ are installed in
	# all images' RO CBFS, compressed
	mkdir -p compressed-assets-ro/"${build_name}"
	find "${froot}"/cbfs-ro-compress/"${build_name}" -mindepth 1 -maxdepth 1 \
		-type f -printf "%P\0" 2>/dev/null | \
		xargs -0 -n 1 -P "$(nproc)" -I '{}' \
		cbfs-compression-tool compress \
			"${froot}"/cbfs-ro-compress/"${build_name}"/'{}' \
			compressed-assets-ro/"${build_name}"/'{}' LZMA

	# files from cbfs-rw-compress/ are installed in
	# all images' RO/RW CBFS, compressed
	mkdir -p compressed-assets-rw/"${build_name}"
	find "${froot}"/cbfs-rw-compress/"${build_name}" -mindepth 1 -maxdepth 1 \
		-type f -printf "%P\0" 2>/dev/null | \
		xargs -0 -n 1 -P "$(nproc)" -I '{}' \
		cbfs-compression-tool compress \
			"${froot}"/cbfs-rw-compress/"${build_name}"/'{}' \
			compressed-assets-rw/"${build_name}"/'{}' LZMA

	# files from cbfs-rw-compress-override/ are installed in
	# all images' RW CBFS, compressed
	mkdir -p compressed-assets-rw-override/"${build_name}"
	find "${froot}"/cbfs-rw-compress-override/"${build_name}" -mindepth 1 \
		-maxdepth 1 -type f -printf "%P\0" 2>/dev/null | \
		xargs -0 -n 1 -P "$(nproc)" -I '{}' \
		cbfs-compression-tool compress \
			"${froot}"/cbfs-rw-compress-override/"${build_name}"/'{}' \
			compressed-assets-rw-override/"${build_name}"/'{}' LZMA
}

# Build firmware images for a given board
# Creates image*.bin for the following images:
#    image.bin          - production image (no serial console)
#    image.serial.bin   - production image with serial console enabled
#    image.dev.bin      - developer image with serial console enabled
#    image.net.bin      - netboot image with serial console enabled
#
# If $2 is set, then it uses "image-$2" instead of "image" and puts images in
# the $2 subdirectory.
#
# If outdir
# Args:
#   $1: Directory containing the input files:
#       coreboot.rom             - coreboot ROM image containing various pieces
#       coreboot.rom.serial      - same, but with serial console enabled
#       depthcharge/depthcharge.elf - depthcharge ELF payload
#       depthcharge/dev.elf      - developer version of depthcharge
#       depthcharge/netboot.elf  - netboot version of depthcharge
#       depthcharge/depthcharge.config - configuration used to build depthcharge image
#       (plus files mentioned above in add_assets)
#   $2: Name to use when naming output files (see note above, can be empty)
#
#   $3: Name of target to build for coreboot (can be empty)
#
#   $4: Name of target to build for depthcharge (can be empty)
#
#   $5: Name of target to build for ec (can be empty)
build_images() {
	local froot="$1"
	local build_name="$2"
	local coreboot_build_target="$3"
	local depthcharge_build_target="$4"
	local ec_build_target="$5"
	local outdir
	local suffix
	local file
	local rom

	local coreboot_orig
	local depthcharge_prefix
	local coreboot_config

	if [ -n "${build_name}" ]; then
		einfo "Building firmware images for ${build_name}"
		outdir="${build_name}/"
		mkdir "${outdir}"
		suffix="-${build_name}"
		coreboot_orig="${froot}/${coreboot_build_target}/coreboot.rom"
		coreboot_config="${froot}/${coreboot_build_target}/coreboot.config"
		depthcharge_prefix="${froot}/${depthcharge_build_target}/depthcharge"
	else
		coreboot_orig="${froot}/coreboot.rom"
		coreboot_config="${froot}/coreboot.config"
		depthcharge_prefix="${froot}/depthcharge"
	fi

	local coreboot_file="coreboot.rom"
	cp "${coreboot_orig}" "${coreboot_file}"
	cp "${coreboot_orig}.serial" "${coreboot_file}.serial"

	local depthcharge
	local depthcharge_dev
	local netboot
	local depthcharge_config

	if use depthcharge; then
		depthcharge="${depthcharge_prefix}/depthcharge.elf"
		depthcharge_dev="${depthcharge_prefix}/dev.elf"
		netboot="${depthcharge_prefix}/netboot.elf"
		depthcharge_config="${depthcharge_prefix}/depthcharge.config"
	fi

	if [[ -d ${froot}/cbfs ]]; then
		die "something is still using ${froot}/cbfs, which is deprecated."
	fi

	if use cros_ec || use wilco_ec || use zephyr_ec; then
		if [[ -n "${ec_build_target}" ]]; then
			einfo "Adding EC for ${ec_build_target}"
			add_ec \
				"${depthcharge_config}" \
				"${coreboot_config}" \
				"${coreboot_file}" \
				"ec" \
				"${froot}/${ec_build_target}"
			add_ec \
				"${depthcharge_config}" \
				"${coreboot_config}" \
				"${coreboot_file}.serial" \
				"ec" \
				"${froot}/${ec_build_target}"
		else
			einfo "Skip adding EC for ${build_name}, no EC target defined."
		fi
	fi

	local pd_folder="${froot}/${ec_build_target}_pd"

	if use pd_sync; then
		add_ec "${depthcharge_config}" "${coreboot_config}" "${coreboot_file}" "pd" "${pd_folder}"
		add_ec "${depthcharge_config}" "${coreboot_config}" "${coreboot_file}.serial" "pd" "${pd_folder}"
	fi

	if use include_altfw; then
		setup_altfw "${coreboot_build_target}" "${coreboot_file}"
		setup_altfw "${coreboot_build_target}" "${coreboot_file}.serial"
	fi

	# Keeps the find commands from failing with directory not found
	mkdir -p "raw-assets-rw/${build_name}"

	check_assets "${coreboot_file}.serial" "${depthcharge_dev}"
	add_assets "${coreboot_file}"
	add_assets "${coreboot_file}.serial"

	build_image "" "${coreboot_file}" "${depthcharge}" "${depthcharge}"

	build_image serial "${coreboot_file}.serial" \
		"${depthcharge}" "${depthcharge}"

	build_image dev "${coreboot_file}.serial" \
		"${depthcharge_dev}" "${depthcharge_dev}"

	# Build a netboot image.
	#
	# The readonly payload is usually depthcharge and the read/write
	# payload is usually netboot. This way the netboot image can be used
	# to boot from USB through recovery mode if necessary.
	build_image net "${coreboot_file}.serial" "${depthcharge}" "${netboot}"

	# Netboot coreboot image is almost the same as the serial one, except that
	# the ME region should be unlocked and GPR0 should be disabled.
	# TODO(phoebewang): Disable GPR0 once ifdtool supports it.
	# ME and GRP0 is only available on Intel platform.
	if use intel_cpu; then
		einfo "Disabling netboot firmware ME lock via ifdtool"
		local ifd_chipset=$( awk \
			'BEGIN{FS="\""} /CONFIG_IFD_CHIPSET=/ { print $2 }' \
			"${coreboot_config}" )
		einfo "Chipset name: ${ifd_chipset}"
		local locked_fw="${outdir}image${suffix}.net.bin"
		local unlocked_fw="${outdir}image${suffix}.net_unlock.bin"
		ifdtool -p "${ifd_chipset}" -u -O "${unlocked_fw}" "${locked_fw}" ||
			die "Failed to unlock ME via ifdtool."
		mv "${unlocked_fw}" "${locked_fw}" ||
			die "Failed to rename ${unlocked_fw} to ${locked_fw}."
	fi

	# Set convenient netboot parameter defaults for developers.
	local name="${build_name:-"${BOARD_USE}"}"
	local bootfile="${PORTAGE_USERNAME}/${name}/vmlinuz"
	local argsfile="${PORTAGE_USERNAME}/${name}/cmdline"
	"${FILESDIR}/netboot_firmware_settings.py" \
		-i "${outdir}image${suffix}.net.bin" \
		--bootfile="${bootfile}" --argsfile="${argsfile}" ||
		die "failed to preset netboot parameter defaults."
	"${FILESDIR}/netboot_firmware_settings.py" \
		-i "${outdir}image${suffix}.dev.bin" \
		--bootfile="${bootfile}" --argsfile="${argsfile}" ||
		die "failed to preset netboot parameter defaults."
	einfo "Netboot configured to boot ${bootfile}, fetch kernel command" \
		"line from ${argsfile}, and use the DHCP-provided TFTP server IP."
}

src_compile() {
	local froot="${CROS_FIRMWARE_ROOT}"
	einfo "Copying static rw assets"

	if [[ -d "${froot}"/cbfs-rw-raw ]]; then
		mkdir raw-assets-rw
		cp -R "${froot}"/cbfs-rw-raw/* raw-assets-rw/ ||
			die "unable to copy files cbfw-rw-raw files"
	fi

	einfo "Compressing static assets"

	if [[ -d ${froot}/rocbfs ]]; then
		die "something is still using ${froot}/rocbfs, which is deprecated."
	fi

	compress_assets "${froot}"

	local fields="coreboot,depthcharge,ec,zephyr-ec"
	local cmd="get-firmware-build-combinations"
	local zephyr_ec
	(cros_config_host "${cmd}" "${fields}" || die) |
	while read -r name; do
		read -r coreboot
		read -r depthcharge
		read -r ec
		read -r zephyr_ec
		einfo "Compressing target assets for: ${name}"
		compress_assets "${froot}" "${name}"
		einfo "Building image for: ${name}"
		if use zephyr_ec; then
			# Zephyr installs under ${froot}/${name}/ec.bin,
			# instead of using the EC build target name.
			if [[ -n "${zephyr_ec}" ]]; then
				ec="${name}"
			elif ! use cros_ec; then
				# Only fallback to legacy EC only if its build is enabled.
				ec=""
			fi
		fi
		build_images "${froot}" "${name}" "${coreboot}" "${depthcharge}" "${ec}"
	done
}

src_install() {
	insinto "${CROS_FIRMWARE_IMAGE_DIR}"
	local fields="coreboot,depthcharge"
	local cmd="get-firmware-build-combinations"
	(cros_config_host "${cmd}" "${fields}" || die) |
	while read -r name; do
		read -r coreboot
		read -r depthcharge
		doins "${name}/image-${name}"*.bin
	done
}
