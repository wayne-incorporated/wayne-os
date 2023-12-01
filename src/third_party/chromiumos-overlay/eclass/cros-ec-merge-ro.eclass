# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-ec-merge-ro.eclass
# @MAINTAINER:
# Chromium OS Firmware Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for merging RO firmware into EC firmware
# @DESCRIPTION:
# Merges a specific RO version of firmware into the firmware that was built
# during the build.
#
# NOTE: When making changes to this class, make sure to modify all the -9999
# ebuilds that inherit it to work around https://issuetracker.google.com/201299127.

if [[ -z "${_ECLASS_CROS_EC_MERGE_RO}" ]]; then
_ECLASS_CROS_EC_MERGE_RO="1"

# Check for EAPI 7+
case "${EAPI:-0}" in
[0123456]) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
*) ;;
esac

inherit cros-ec-utils

# Make sure that private files ebuild has run since it creates the symlink
# used in the src_install step below.
# We also use cros_config_host below.
DEPEND="
	virtual/chromeos-ec-private-files
"
BDEPEND="
	chromeos-base/chromeos-config-host
"

# @FUNCTION: cros-ec-merge-ro_do_merge
# @USAGE: <RO firmware path> <RW firmware path>
# @INTERNAL
# @DESCRIPTION:
# Copy RO firmware from firmware specified in <RO firmware path> and RW firmware
# from <RW firmware path> into a new file. Returns the filename
# of the new file.
cros-ec-merge-ro_do_merge() {
	local ec_ro="$1"
	local ec_rw="$2"

	einfo "Merging RO firmware"

	# Print RO and RW versions.
	local ro_version_string
	local rw_version_string

	ro_version_string="$(cros-ec-utils-get_firmware_ro_version "${ec_ro}" || die)"
	rw_version_string="$(cros-ec-utils-get_firmware_rw_version "${ec_rw}" || die)"

	einfo "Using firmware RO version: ${ro_version_string}"
	einfo "Using firmware RW version: ${rw_version_string}"

	# Use RW firmware version as file name.
	local new_file="${rw_version_string}.bin"
	# fmap_rw_section[0]="EC_RW"
	# fmap_rw_section[1]=offset
	# fmap_rw_section[2]=size (decimal)
	local fmap_rw_section
	IFS=" " read -r -a fmap_rw_section <<< "$(dump_fmap -p "${ec_ro}" EC_RW \
		|| die)"

	# Inject RW into the existing RO file.
	einfo "Merging files..."
	cp "${ec_ro}" "${new_file}" || die
	dd if="${ec_rw}" of="${new_file}" \
		bs=1 skip="${fmap_rw_section[1]}" seek="${fmap_rw_section[1]}" \
		count="${fmap_rw_section[2]}" conv=notrunc status=none || die

	echo "${new_file}"
}

# @FUNCTION: cros-ec-merge-ro_src_install
# @DESCRIPTION:
# Copy pre-built RO firmware into RW firmware that was built.
cros-ec-merge-ro_src_install() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	# Use our specified board.
	local target="${FIRMWARE_EC_BOARD}"

	local firmware_bin_dir="$(readlink -f \
		"${S}/private/fingerprint/fpc/firmware-bin")"

	if [[ ! -d "${firmware_bin_dir}" ]]; then
		einfo "No RO firmware found. This is expected in a public build."
		return 0
	fi

	# If cros_config provides RO firmware version, then use it. The RO firmware
	# version does not have to be specified, in which case cros_config_host will
	# exit with success and not print any firmware version.
	# In that case, we want to use the "default" RO firmware, so validate
	# that there is exactly one RO binary.
	local fw_target="${target%%_fp}"
	local ro_version
	ro_version="$(cros_config_host \
		get-fpmcu-firmware-ro-version "${fw_target}" || die)"

	local ro_fw
	if [[ -n ${ro_version} ]]; then
		einfo "RO version specified: ${ro_version}."
		ro_fw="$(ls "${firmware_bin_dir}/${fw_target}/RO/${ro_version}.bin" || die)"
	else
		einfo "No RO version specified; using default."
		local ro_fw_count=0
		ro_bin_files=("${firmware_bin_dir}/${fw_target}/RO/"*.bin)
		ro_fw_count=${#ro_bin_files[@]}
		if [[ ${ro_fw_count} -ne 1 ]]; then
			eerror "Incorrect number of RO firmware files found: ${ro_fw_count}"
			die
		fi

		ro_fw="${ro_bin_files[0]}"
	fi

	local rw_fw="${WORKDIR}/build_${target}/${target}/ec.bin"
	local merged_fw="$(cros-ec-merge-ro_do_merge "${ro_fw}" "${rw_fw}")"
	cp "${merged_fw}" "${rw_fw}" || die
}

EXPORT_FUNCTIONS src_install

fi  # _ECLASS_CROS_EC_MERGE_RO
