# Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit cros-binary

DESCRIPTION="Topology binary files used to support/configure LPE Audio"
LICENSE="LICENCE.adsp_sst"
SLOT="0"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-nami-${PV}.tar.xz"
KEYWORDS="-* x86 amd64"

RDEPEND="
	media-libs/kbl-hotword-support
"

DEPEND="${RDEPEND}"
IUSE="kernel-5_4"

S=${WORKDIR}

src_install() {
	FWPATH=lib/firmware
	FWNAME=9d71-GOOGLE-NAMIMAX-0-tplg
	KERNEL=4_4
	if use kernel-5_4; then
		KERNEL=5_4
	fi

	SRCNAME=${FWNAME}-${KERNEL}.bin
	DSTNAME=${FWNAME}.bin
	mv ${FWPATH}/${SRCNAME} ${FWPATH}/${DSTNAME}

	insinto /${FWPATH}
	doins ${FWPATH}/${DSTNAME}
}
