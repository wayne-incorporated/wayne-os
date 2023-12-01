# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="PS8751-A3 Firmware Binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="Google-Partners-Website"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

# We must ensure that the older private package is not installed
DEPEND="
	!sys-firmware/parade-ps8751a3
	!sys-boot/chromeos-firmware-ps8751
"

RDEPEND="${DEPEND}"

src_install() {
	local fw_rev_hex=$(printf '%02x' "$PV")
	local bf=ps8751_a3.bin
	local hf=ps8751_a3.hash

	printf "\\xa3\\x${fw_rev_hex}" > "${hf}"
	insinto /firmware/ps8751
	newins "${hf}" "${hf}"
	newins "${P}/ps8751_a3_0x${fw_rev_hex}.bin" "${bf}"
}
