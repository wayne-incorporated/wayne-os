# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="PS8815-A1 Firmware Binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="Google-Partners-Website"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

# We must ensure that the older private package is not installed
DEPEND="
	!sys-boot/chromeos-firmware-ps8815
"

RDEPEND="${DEPEND}"

# Here are the steps to uprev the PS8815 firmware.
#
# 1) Unzip the .zip file emailed from the vendor.
# 2) Convert from hex to bin.
#    ex: objcopy -I ihex --output-target=binary PS8815_FW_0x06_20200515_A1.hex \
#          parade-ps8815a1-firmware-6/ps8815_a1_0x06.bin
# 3) Tarball it up using XZ, including the right directory.
#    ex: tar -cJf parade-ps8815a1-firmware-6.tar.xz \
#          parade-ps8815a1-firmware-6/ps8815_a1_0x06.bin
# 4) Then upload it at https://pantheon.corp.google.com/storage/browser/chromeos-localmirror/distfiles
# 5) On the uploaded file, click the three-dot-menu, "Edit
#    Permissions", click on ADD ENTRY, then set:
#      Entity: "Public"
#      Name:   "allUsers"
#      Access: "Reader"
# 6) Finally run 'ebuild parade-ps8815a1-firmware-6.ebuild manifest'

src_install() {
	local fw_rev_hex=$(printf '%02x' "${PV}")
	local bf=ps8815_a1.bin
	local hf=ps8815_a1.hash

	printf "\\xa1\\x${fw_rev_hex}" > "${hf}"
	insinto /firmware/ps8815
	newins "${hf}" "${hf}"
	newins "${P}/ps8815_a1_0x${fw_rev_hex}.bin" "${bf}"
}
