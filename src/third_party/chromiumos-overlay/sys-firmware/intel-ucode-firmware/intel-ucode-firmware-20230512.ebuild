# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the BSD license.

EAPI=7

DESCRIPTION="Intel processor microcode updates"
HOMEPAGE="https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files"

SRC_URI="https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/archive/microcode-${PV}.tar.gz"
LICENSE="intel-ucode"
KEYWORDS="-* amd64"
SLOT="0/${PVR}"

S="${WORKDIR}/Intel-Linux-Processor-Microcode-Data-Files-microcode-${PV}"

RDEPEND="!sys-firmware/intel-microcode"

src_install() {
	insinto /lib/firmware
	doins -r "${S}/intel-ucode"
}
