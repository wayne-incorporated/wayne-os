# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Sound Open Firmware (SOF) binary files"

HOMEPAGE="https://www.sofproject.org https://github.com/thesofproject/sof https://github.com/thesofproject/sof-bin"
SRC_URI="https://github.com/thesofproject/sof-bin/releases/download/v${PV}/sof-bin-v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

S=${WORKDIR}/sof-bin-v${PV}

src_install() {
	# All "sof-cml" binary files are symlinks to "sof-cnl" binary files.
	# So we need to copy all "sof-cnl" files as well, for CometLake.
	insinto /lib/firmware/intel/sof/community
	doins "sof-v${PV}"/community/*-{cml,cnl}*

	insinto /lib/firmware/intel/sof/intel-signed
	doins "sof-v${PV}"/intel-signed/*-{cml,cnl}*

	insinto /lib/firmware/intel/sof
	doins "sof-v${PV}"/*-{cml,cnl}*

	# Install all CometLake topology files.
	insinto /lib/firmware/intel/sof-tplg
	doins "sof-tplg-v${PV}"/*-cml*
}
