# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=5

DESCRIPTION="Comet Lake SOF firmware binary"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-cml-${PV}.tar.xz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"
IUSE="kernel-5_15"

S=${WORKDIR}/${PN}-cml-${PV}

src_install() {
	if use kernel-5_15; then
		insinto /lib/firmware/intel/sof/community
	else
		insinto /lib/firmware/intel/sof
	fi

	doins sof-cnl.ri
	dodoc README
}
