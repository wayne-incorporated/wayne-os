# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} pypy3 )
inherit python-any-r1

DESCRIPTION="PS8815-A2 Application Firmware Binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="Google-Partners-Website"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

DEPEND=""

RDEPEND="${DEPEND}"

BDEPEND="${PYTHON_DEPS}"

# Here are the steps to uprev the PS8815 app firmware.
#
# Parade provides two firmware file types:
#     Combined bootloader+application that is programmed into bank 3
#     Application only that is programmed into bank 2
#
# This ebuild supports adding the application only firmware to CBFS.
#
# 1) Unzip the .zip file emailed from the vendor.
# 2) Convert from hex to bin.
#    ex: objcopy -I ihex --output-target=binary \
#          --gap-fill 0xff \
#          PS8815_FW_0x24_20220105_A2.hex \
#          parade-ps8815a2-app-firmware-36/ps8815_a2_app_0x24.bin
# 3) Tarball it up using XZ, including the right directory.
#    ex: tar -cJf parade-ps8815a2-app-firmware-36.tar.xz \
#          parade-ps8815a2-app-firmware-36/ps8815_a2_app_0x24.bin
# 4) Then upload it at https://pantheon.corp.google.com/storage/browser/chromeos-localmirror/distfiles
# 5) On the uploaded file, click the three-dot-menu, "Edit access",
#    click on ADD ENTRY, then set:
#      Entity: "Public"
#      Name:   "allUsers"
#      Access: "Reader"
# 6) Finally run 'ebuild parade-ps8815a2-app-firmware-36.ebuild manifest'

src_install() {
	local fw_rev_hex=$(printf '%02x' "${PV}")
	local bf=ps8815_a2.bin
	local hf=ps8815_a2.hash
	local asum=app_checksum.py

	printf "\\xa2\\x${fw_rev_hex}" > "${hf}"
	"${PYTHON}" "${FILESDIR}/${asum}" \
		-r "${P}/ps8815_a2_app_0x${fw_rev_hex}.bin" \
		-w "${bf}" || \
		die "${asum} failed!"

	insinto /firmware/ps8815_app
	newins "${hf}" "${hf}"
	newins "${bf}" "${bf}"
}
