# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="PS8805-A2 Firmware Binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="Google-Partners-Website"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

# We must ensure that the older private package is not installed
DEPEND="
	!sys-boot/chromeos-firmware-ps8805
"

RDEPEND="${DEPEND}"

# Here are the steps to uprev the PS8805 firmware.
#
# 1) Unzip the .zip file emailed from the vendor.
# 2) Convert from hex to bin.
#    ex: objcopy -I ihex --output-target=binary PS8805_FW_0x0C_20180810_A2.hex \
#          parade-ps8805a2-firmware-12/ps8805_a2_0x0c.bin
# 3) Tarball it up using XZ, including the right directory.
#    ex: tar -cJf parade-ps8805a2-firmware-12.tar.xz \
#          parade-ps8805a2-firmware-12/ps8805_a2_0x0c.bin
# 4) Then upload it at https://pantheon.corp.google.com/storage/browser/chromeos-localmirror/distfiles
# 5) On the uploaded file, click the three-dot-menu, "Edit Permissions", and
#    add a new User "allUsers" with Reader permission.
# 6) Finally run `ebuild parade-ps8805a2-firmware-8.ebuild manifest`

src_install() {
	local fw_rev_hex=$(printf '%02x' "${PV}")
	local bf=ps8805_a2.bin
	local hf=ps8805_a2.hash

	printf "\\xa2\\x${fw_rev_hex}" > "${hf}"
	insinto /firmware/ps8805
	newins "${hf}" "${hf}"
	newins "${P}/ps8805_a2_0x${fw_rev_hex}.bin" "${bf}"
}
