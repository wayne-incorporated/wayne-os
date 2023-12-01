# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Ebuild that installs the chromeos disk firmware payload."
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tbz2"

LICENSE="Google-Partners-Website"
SLOT="0"
KEYWORDS="-* amd64 x86"

DEPEND=""
RDEPEND="${DEPEND}
	chromeos-base/disk_updater"

S=${WORKDIR}

src_install() {
	local fw_file i
	local fw_dir="/opt/google/disk/firmware"
	local fw_rules="${D}/${fw_dir}/rules"

	insinto /opt
	doins -r opt/*

	# Create symlink at /lib/firmware to the eMMC firmware binaries.
	# The firmware files will be downloaded from the root partition by the
	# kernel through udev, and then uploaded to the eMMC device.
	# The firmware names are the 5th parameters of the rule file:
	# <device part number> <old fw version> <new fw version> <options> <image>
	for i in $(cut -d ' ' -f 5 "${fw_rules}"); do
		fw_file="${D}/${fw_dir}/${i}"
		if [[ -f "${fw_file}" ]]; then
			dosym "${fw_dir}/${i}" "/lib/firmware/${i}"
		fi
	done
}
