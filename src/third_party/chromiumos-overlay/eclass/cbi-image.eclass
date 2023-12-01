# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
#
# @ECLASS: cbi-image.eclass
# @MAINTAINER:
# Chromium OS Firmware Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building Cros Board Info (CBI) images
# @DESCRIPTION:
# CBI is the Chrome OS standard data format for storing board version, OEM,
# SKU, etc. This library provides helper functions for each board to create
# custom CBI images.

# Check for EAPI 5+
case "${EAPI:-0}" in
	[01234])
		die "Unsupported EAPI=${EAPI:-0} (too old) for ${ECLASS}"
		;;
	*) ;;
esac

# @ECLASS-VARIABLE: CROS_CBI_IMAGE_DIR
# @DESCRIPTION: The directory where output images are stored.
CROS_CBI_IMAGE_DIR="/firmware/cbi"

# @ECLASS-VARIABLE: EEPROM_SIZE
# @DESCRIPTION: The size of the output image files in bytes.
EEPROM_SIZE=256

# @FUNCTION: make_cbi
# @USAGE: <Prefix for output files> <oem id> <sku id>
# @DESCRIPTION: Build one CBI image
make_cbi() {
	[[ $# -ne 3 ]] && die "Usage: ${FUNCNAME} <prefix> <oem id> <sku id>"
	local prefix="$1"
	local oemid="$2"
	local skuid="$3"

	cbi-util create --file "${prefix}_${skuid%%:*}.bin" \
		--size "${EEPROM_SIZE}" --board_version "${BOARD_VERSION}" \
		--oem_id "${oemid}" --sku_id "${skuid}" \
		|| die "Failed to create CBI image"
}

# @FUNCTION: make_all_cbi
# @USAGE: <oem name> <oem id>
# @DESCRIPTION:
# Build CBI images for all SKU IDs listed in SKU_IDS_<oem name> array, which
# is supposed to be provided by the caller.
make_all_cbi() {
	[[ $# -ne 2 ]] && die "Usage: ${FUNCNAME} <oem name> <oem id>"
	local oem_name="$1"
	local skuids="SKU_IDS_${oem_name}[@]"
	local oemid="$2"
	local i

	for i in "${!skuids}"; do
		make_cbi "cbi_${oem_name}" "${oemid}" "${i}"
	done
}

# @FUNCTION: cbi-image_install
# @USAGE:
# @DESCRIPTION: Install the CBI image files to $CROS_CBI_IMAGE_DIR
cbi-image_install() {
	[[ $# -ne 0 ]] && die "Usage: ${FUNCNAME}"
	insinto "${CROS_CBI_IMAGE_DIR}"
	doins cbi_*.bin
}
