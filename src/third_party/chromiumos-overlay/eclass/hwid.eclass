# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# $Header: $

# @ECLASS: hwid.eclass
# @MAINTAINER:
# Chromium OS Brillo team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: Eclass for setting up HWID_OVERRIDE in /etc/lsb-release

IUSE="hwid_override"

# @FUNCTION: dohwid
# @USAGE: <hwid>
# @DESCRIPTION:
# Appends hwid to /etc/lsb-release.
# The inputs are not currently restricted in any way though most look like:
# ^BOARD .* .
# Additional note, this must be run after doappid in the chromeos-bsp file.
# @CODE
# dohwid "TACO ALPHA 1"
# @CODE
# will append
# @CODE
# HWID_OVERRIDE=TACO ALPHA 1
# @CODE
# to /etc/lsb-release.
dohwid() {
	[[ $# -eq 1 && -n $1 ]] || die "Usage: ${FUNCNAME} <hwid>"
	local hwid="$1"

	# Actually check if we'll use the hwid_override.
	if ! use hwid_override ; then
	  die "hwid_override not set"
	fi

	dodir /etc
	local lsb="${D}/etc/lsb-release"
	cat <<-EOF >> "${lsb}"
	HWID_OVERRIDE=${hwid}
	EOF
}
