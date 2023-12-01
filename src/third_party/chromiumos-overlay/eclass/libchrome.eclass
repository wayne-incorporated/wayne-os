# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: libchrome.eclass
# @MAINTAINER:
# ChromiumOS Build Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for managing dependencies on libchrome
# @DESCRIPTION:
# Our base library libchrome is slotted and is used by a lot of packages. All
# the version numbers need to be updated whenever we uprev libchrome. This
# eclass centralizes the logic used to depend on libchrome and sets up the
# environment variables to reduce the amount of change needed.

inherit cros-debug libchrome-version

# Require a recent one from time to time to help keep people up-to-date.
# shellcheck disable=SC2154
RDEPEND="
	>=chromeos-base/libchrome-0.0.1-r${REQUIRED_LIBCHROME_EBUILD_VERSION}:0=[cros-debug=]
"

DEPEND="${RDEPEND}"

# @FUNCTION: libchrome_ver
# @DESCRIPTION:
# Output current libchrome BASE_VER, from SYSROOT-installed BASE_VER file.
# LIBCHROME_SYSROOT can be set.
# If LIBCHROME_SYSROOT is set, it read $LIBCHROME_SYSROOT-installed BASE_VER
# file.
libchrome_ver() {
	local basever_file="${SYSROOT}/usr/share/libchrome/BASE_VER"
	if [[ -n "${LIBCHROME_SYSROOT}" ]]; then
		basever_file="${LIBCHROME_SYSROOT}/usr/share/libchrome/BASE_VER"
	fi
	cat "${basever_file}" || die "cat ${basever_file} error."
}
