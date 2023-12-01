# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

if [[ -z "${EBUILD}" ]]; then
	die "This eclass needs EBUILD environment variable."
fi

# @ECLASS: cros-cpfe.eclass
# @MAINTAINER:
# ChromiumOS Build Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for fetching binary components from CPFE binary host.
# @DESCRIPTION:
# Binary components (especially for private usage) are usually uploaded by CPFE
# (Chrome OS Parnter Frontend, https://www.google.com/chromeos/partner/fe/ ) and
# then retrieved by writing special SRC_URI with board name and overlay path.
#
# The path format and backend for CPFE binary host has been changed several
# times, including changes in user / overlay name and the changes from BCS
# (Binary Component Server) to Google Storage.
#
# To simplify that, inherit this eclass and build a simpler SRC_URI. Example:
#  SRC_URI=${CROS_CPFE_URL}/${P}.tbz2

# @ECLASS-VARIABLE: CROS_CPFE_BOARD_OVERLAY
# @DESCRIPTION:
# Name of current board overlay. Example: overlay-variant-peach-pit-private
: "${CROS_CPFE_BOARD_OVERLAY:=$(
	# EBUILD will be the full path to the ebuild file.
	IFS="/"
	set -- ${EBUILD}
	# Chop off the ebuild, the $PN dir, and the $CATEGORY dir.
	n=$(( $# - 3 ))
	echo "${!n}"
)}"

# @ECLASS-VARIABLE: CROS_CPFE_OVERLAY_NAME
# @DESCRIPTION:
# Overlay name on CPFE binary host. Example: variant-peach-pit-private
: "${CROS_CPFE_OVERLAY_NAME:=${CROS_CPFE_BOARD_OVERLAY#overlay-}}"

# @ECLASS-VARIABLE: CROS_CPFE_USER_NAME
# @DESCRIPTION:
# User name for board on CPFE binary host. Example: pit-private
: "${CROS_CPFE_USER_NAME:=${CROS_CPFE_OVERLAY_NAME#variant-*-}}"

# @ECLASS-VARIABLE: CROS_CPFE_HOME
# @DESCRIPTION:
# User's home URL on CPFE binary host.
: "${CROS_CPFE_HOME:=gs://chromeos-binaries/HOME/bcs-${CROS_CPFE_USER_NAME}}"

# @ECLASS-VARIABLE: CROS_CPFE_PATH
# @DESCRIPTION:
# Package directory path on CPFE binary host.
: "${CROS_CPFE_PATH:=${CROS_CPFE_BOARD_OVERLAY}/${CATEGORY}/${PN}}"

# @ECLASS-VARIABLE: CROS_CPFE_URL
# @DESCRIPTION:
# Complete URL for package data on CPFE binary host.
: "${CROS_CPFE_URL:=${CROS_CPFE_HOME}/${CROS_CPFE_PATH}}"

# Force archive fetching from the CPFE GS buckets instead of the common CrOS mirror buckets.
# By default, emerge will only fetch archives from our mirrors regardless of SRC_URI settings.
RESTRICT+=" mirror"
