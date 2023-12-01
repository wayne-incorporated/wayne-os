# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="PS8755-A2 Firmware Binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="Google-Partners-Website"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

DEPEND=""
RDEPEND="${DEPEND}"

# Here are the steps to uprev the PS8755 firmware.
#
# 1) Unzip the .zip file emailed from the vendor.
# 2) Convert from hex to bin.
#    ex: objcopy -I ihex --output-target=binary PS8755_FW_0x02_20200813.hex \
#          parade-ps8755a2-firmware-2/ps8755_a2_0x02.bin
# 3) Tarball it up using XZ, including the right directory.
#    ex: tar -cJf parade-ps8755a2-firmware-2.tar.xz \
#          parade-ps8755a2-firmware-2/ps8755_a2_0x02.bin
# 4) Then upload it at https://pantheon.corp.google.com/storage/browser/chromeos-localmirror/distfiles
# 5) On the uploaded file, click the three-dot-menu, "Edit Permissions", and
#    add a new entry for Public "allUsers" with Reader permission.
# 6) Finally run `ebuild parade-ps8755a2-firmware-2.ebuild manifest`
src_install() {
	local fw_rev_hex=$(printf '%02x' "${PV}")
	local bf=ps8755_a2.bin
	local hf=ps8755_a2.hash

	printf '0xa2 0x%02x' "${PV}" | xxd -r > "${hf}"
	insinto /firmware/ps8755
	newins "${hf}" "${hf}"
	newins "${P}/ps8755_a2_0x${fw_rev_hex}.bin" "${bf}"
}
