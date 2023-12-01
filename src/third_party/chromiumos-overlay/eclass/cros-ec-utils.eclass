# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-ec-utils.eclass
# @MAINTAINER:
# Chromium OS Firmware Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building Chromium OS firmware
# @DESCRIPTION:
# Common helper functions for working with Chromium OS EC firmware.
#
# NOTE: When making changes to this class, make sure to modify all the -9999
# ebuilds that inherit it (e.g., chromeos-fpmcu-release*) to work around
# https://issuetracker.google.com/201299127.

if [[ -z "${_ECLASS_CROS_EC_UTILS}" ]]; then
_ECLASS_CROS_EC_UTILS="1"

# Check for EAPI 7+.
case "${EAPI:-0}" in
0|1|2|3|4|5|6) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
*) ;;
esac

# @FUNCTION: get_firmware_version
# @USAGE: <firmware path> <firmware ID field>
# @INTERNAL
# @DESCRIPTION:
# Read the firmware version from the provided file.
get_firmware_version() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	local file="${1}"
	local fw_id_field="${2}"
	local version_string
	local -a fmap_fwid

	IFS=" " read -r -a fmap_fwid <<<"$(dump_fmap -p "${file}" "${fw_id_field}" \
		|| die)"
	# Values in array after running above command:
	#   fmap_fwid[0]="${fw_id_field}"
	#   fmap_fwid[1]=offset
	#   fmap_fwid[2]=size
	version_string="$(dd bs=1 skip="${fmap_fwid[1]}" \
		count="${fmap_fwid[2]}" if="${file}" status=none || die)"
	echo "${version_string}"
}

# @FUNCTION: get_firmware_rw_version
# @USAGE: <RW firmware path>
# @DESCRIPTION:
# Read the read-write (RW) firmware version from the provided file.
cros-ec-utils-get_firmware_rw_version() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	local file="${1}"
	get_firmware_version "${file}" "RW_FWID"
}

# @FUNCTION: get_firmware_ro_version
# @USAGE: <RO firmware path>
# @DESCRIPTION:
# Read the read-only (RO) firmware version from the provided file.
cros-ec-utils-get_firmware_ro_version() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	local file="${1}"
	get_firmware_version "${file}" "RO_FRID"
}

fi  # _ECLASS_CROS_EC_UTILS
