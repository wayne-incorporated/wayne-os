# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="PS8745-A2 Firmware Binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="Google-Partners-Website"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

# Here are the steps to uprev the PS8745 firmware.
#
# 1) Unzip the .zip file emailed from the vendor.
# 2) Convert from hex to bin.
#    ex: objcopy -I ihex --output-target=binary \
#         --gap-fill 0xff --pad-to 0x10000 \
#          PS8745_FW_0x02_20220622_A2_whole.hex \
#          parade-ps8745a2-firmware-2/ps8745_a2_0x02.bin
# 3) Tarball it up using XZ, including the right directory.
#    ex: tar -cJf parade-ps8745a2-firmware-2.tar.xz \
#          parade-ps8745a2-firmware-2/ps8745_a2_0x02.bin
# 4) Then upload it at https://pantheon.corp.google.com/storage/browser/chromeos-localmirror/distfiles
# 5) On the uploaded file, click the three-dot-menu, "Edit access",
#    click on ADD ENTRY, then set:
#      Entity: "Public"
#      Name:   "allUsers"
#      Access: "Reader"
# 6) Finally run 'ebuild parade-ps8745a2-firmware-2.ebuild manifest'

src_install() {
	local fw_rev_hex=$(printf '%02x' "${PV}")
	local bf=ps8745_a2.bin
	local hf=ps8745_a2.hash

	printf "\\xa2%b" "\\x${fw_rev_hex}" > "${hf}" || die
	insinto /firmware/ps8745
	newins "${hf}" "${hf}"
	newins "${P}/ps8745_a2_0x${fw_rev_hex}.bin" "${bf}"
}
