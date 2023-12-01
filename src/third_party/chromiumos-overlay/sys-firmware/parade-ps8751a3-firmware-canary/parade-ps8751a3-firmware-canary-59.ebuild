# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
#
# This package is for canarying new Parade PS8751 TCPC firmware versions
# on a subset of USB ports on a device, ahead of updating the revision of
# the main parade-ps8751a3-firmware package on the device.
#
# This uses the same set of firmware binary blob tarballs as the main
# package.  This exists separately so that two revisions can be installed
# concurrently.

EAPI=6

DESCRIPTION="PS8751-A3 Firmware Binary - Canary Package"
SRC_URI="gs://chromeos-localmirror/distfiles/parade-ps8751a3-firmware-${PV}.tar.xz"

LICENSE="Google-TOS"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

src_install() {
	local fw_rev_hex=$(printf '%02x' "$PV")
	local bf=ps8751_a3_canary.bin
	local hf=ps8751_a3_canary.hash

	printf "\\xa3\\x${fw_rev_hex}" > "${hf}"
	insinto /firmware/ps8751
	newins "${hf}" "${hf}"
	newins "parade-ps8751a3-firmware-${PV}/ps8751_a3_0x${fw_rev_hex}.bin" "${bf}"
}
