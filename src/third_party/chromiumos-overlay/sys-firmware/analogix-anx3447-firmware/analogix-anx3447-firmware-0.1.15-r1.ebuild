# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="ANX3447 Firmware Binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"

# Here are the steps to uprev the ANX3447 firmware.
#
# 1) Unzip the .zip file obtained from the vendor.
# 2) Convert from hex to bin.
#    ex: objcopy -I ihex --output-target=binary \
#         --gap-fill 0xff --pad-to 0xE000 \
#          Liberty_tcpc_v0.1.15.hex \
#          analogix-anx3447-firmware-0.1.15/anx3447_ocm_0x0115.bin
# 3) Tarball it up using XZ, including the right directory.
#    ex: tar -cJf analogix-anx3447-firmware-0.1.15.tar.xz \
#          analogix-anx3447-firmware-0.1.15/anx3447_ocm_0x0115.bin
# 4) Follow https://chromium.googlesource.com/chromiumos/docs/+/HEAD/archive_mirrors.md#getting-files-onto-localmirror
#    to upload the zipped file.
# 5) Finally run 'ebuild analogix-anx3447-firmware-0.1.15-r1.ebuild manifest'
src_install() {
	local fw_rev_hex=$(printf '%s' "${PV}")
	# 0.1.15 -> 1
	local fw_main_rev=$(ver_cut 2)
	# 0.1.15 -> 15
	local fw_build_rev=$(ver_cut 3)
	local bf=anx3447_ocm.bin
	local hf=anx3447_ocm.hash

	echo -n -e "\\x${fw_main_rev}\\x${fw_build_rev}" > "${hf}"
	insinto /firmware/anx3447
	doins "${hf}"
	newins "${P}/anx3447_ocm_${fw_rev_hex}.bin" "${bf}"
}
