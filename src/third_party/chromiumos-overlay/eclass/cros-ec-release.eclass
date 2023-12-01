# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-ec-release.eclass
# @MAINTAINER:
# Chromium OS Firmware Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for building Chromium OS release firmware
# @DESCRIPTION:
# Release firmware using the EC code base needs to be built from specific
# branches/commits and must be signed by the signing daemon. This eclass
# provides a standardized mechanism for that process by building for a specific
# EC "board" and installing it into /build/<board>/<FPMCU_board>/release
# so that the signer can pick it up. Note that this doesn't install the
# firmware into the rootfs; that has to be done by a separate ebuild since the
# signer runs after the build.
#
# NOTE: When making changes to this class, make sure to modify all the -9999
# ebuilds that inherit it (e.g., chromeos-fpmcu-release*) to work around
# https://issuetracker.google.com/201299127.

if [[ -z "${_ECLASS_CROS_EC_RELEASE}" ]]; then
_ECLASS_CROS_EC_RELEASE="1"

# Check for EAPI 6+.
case "${EAPI:-0}" in
0|1|2|3|4|5) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
*) ;;
esac

# @ECLASS-VARIABLE: FIRMWARE_EC_BOARD
# @DEFAULT_UNSET
# @DESCRIPTION:
# EC "board" to build.
: "${FIRMWARE_EC_BOARD:=}"

if [[ -z "${FIRMWARE_EC_BOARD}" ]]; then
	die "FIRMWARE_EC_BOARD must be specified in ebuild."
fi

# @ECLASS-VARIABLE: FIRMWARE_EC_RELEASE_REPLACE_RO
# @DEFAULT_UNSET
# @DESCRIPTION:
# By default the RO version in the binary will match the RW version. Use this
# variable to tell the build to replace the RO version with the factory-shipped
# version.
: "${FIRMWARE_EC_RELEASE_REPLACE_RO:="no"}"

inherit cros-ec cros-ec-merge-ro

DESCRIPTION="Chrome OS EC release firmware for ${FIRMWARE_EC_BOARD}."

# Avoid all modification of the firmware binaries; the binaries installed on
# the rootfs by this ebuild must exactly match the binaries copied from git.
#
# binchecks: disable all QA checks for binaries
# strip: final binaries will not be stripped of debug symbols
RESTRICT+="binchecks strip"

# @FUNCTION: get_ec_boards
# @INTERNAL
# @DESCRIPTION:
# This function overrides the get_ec_boards in cros-ec-board.eclass.
get_ec_boards() {
	EC_BOARDS=("${FIRMWARE_EC_BOARD}")
	einfo "Building for board: ${EC_BOARDS[*]}"
}

# @FUNCTION: cros-ec-release_src_prepare
# @DESCRIPTION:
# Override src_prepare in cros-ec-board.eclass.
# Set compilation to EC source directory and make sure private
# source files are in source directory (if private source is available).
cros-ec-release_src_prepare() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	eapply_user

	# We want compilation to happen in the EC source directory.
	S+="/platform/ec"

	# Link the private sources in the private/ sub-directory.
	ln -sfT "${SYSROOT}/firmware/${FIRMWARE_EC_BOARD}/release/ec-private" \
		"${S}/private" || die
}

# @FUNCTION: cros-ec-release_src_install
# @DESCRIPTION:
# Override install in cros-ec-board.eclass so that we only install
# FIRMWARE_EC_BOARD into release directory.
cros-ec-release_src_install() {
	debug-print-function "${FUNCNAME[0]}" "$@"

	# Run the RO replacement process if requested.
	if [[ "${FIRMWARE_EC_RELEASE_REPLACE_RO}" == "yes" ]]; then
		cros-ec-merge-ro_src_install
	fi

	cros-ec_set_build_env

	# Use our specified board.
	local target="${FIRMWARE_EC_BOARD}"

	cros-ec_board_install "${target}" "${WORKDIR}/build_${target}" \
		"/firmware/${target}/release" "" \
		|| die "Couldn't install ${target}"
}

EXPORT_FUNCTIONS src_prepare src_install

fi  # _ECLASS_CROS_EC_RELEASE
