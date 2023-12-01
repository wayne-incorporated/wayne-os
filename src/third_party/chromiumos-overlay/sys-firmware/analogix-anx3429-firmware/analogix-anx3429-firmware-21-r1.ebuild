# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="ANX3429 Firmware Binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

# We must ensure that the older private package is not installed
DEPEND="
	!sys-firmware/analogix-anx3429
	!sys-boot/chromeos-firmware-anx3429
"

RDEPEND="${DEPEND}"

src_install() {
	local fw_rev_hex=$(printf '%02x' "$PV")
	local bf=anx3429_ocm.bin
	local hf=anx3429_ocm.hash

	printf "\\x${fw_rev_hex}" > "${hf}"
	insinto /firmware/anx3429
	newins "${hf}" "${hf}"
	newins "${P}/anx3429_ocm_0x${fw_rev_hex}.bin" "${bf}"
}