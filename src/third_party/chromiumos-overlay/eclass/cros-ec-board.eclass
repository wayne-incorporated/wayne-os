# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

#
# Original Author: The ChromiumOS Authors <chromium-os-dev@chromium.org>
# Purpose: Library for handling building of ChromiumOS packages
#
#

# @ECLASS-VARIABLE: EC_BOARDS
# @DESCRIPTION:
#  This class contains function that lists the name of embedded
#  controllers for a given system.
#  When found, the array EC_BOARDS is populated.
#  For example, for a falco machine, EC_BOARDS = [ "falco" ]
#  For samus, EC_BOARDS = [ "samus", "samus_pd" ]
#
#  The firmware for these ECs can be found in platform/ec/build

# Check for EAPI 4+
case "${EAPI:-0}" in
4|5|6|7) ;;
*) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

inherit cros-unibuild

IUSE="cros_host unibuild"
REQUIRED_USE="|| ( cros_host unibuild )"

# Echo the current boards
get_ec_boards()
{
	EC_BOARDS=()
	if use cros_host; then
		# We are building for the purpose of emitting host-side tools.
		EC_BOARDS=(host)
		return
	fi

	EC_BOARDS+=($(cros_config_host get-firmware-build-targets ec))
	EC_BOARDS+=($(cros_config_host get-firmware-build-targets ish))

	if [[ ${#EC_BOARDS[@]} -eq 0 ]]; then
		einfo "No boards found."
		return
	fi
	einfo "Building for boards: ${EC_BOARDS[*]}"
}
