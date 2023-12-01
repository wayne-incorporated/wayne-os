# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Sound Open Firmware (SOF) binary files"

HOMEPAGE="https://www.sofproject.org https://github.com/thesofproject/sof https://github.com/thesofproject/sof-bin"
SRC_URI="https://github.com/thesofproject/sof-bin/releases/download/v${PV}/sof-bin-v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="-* amd64"
IUSE=""

S=${WORKDIR}/sof-bin-v${PV}

src_install() {
	# All "sof-glk" binary files are symlinks to "sof-apl" binary files.
	# So we need to copy all "sof-apl" files as well, for GeminiLake.
	insinto /lib/firmware/intel/sof/community
	doins "sof-v${PV}"/community/*-{apl,glk}*

	insinto /lib/firmware/intel/sof/intel-signed
	doins "sof-v${PV}"/intel-signed/*-{apl,glk}*

	insinto /lib/firmware/intel/sof
	doins "sof-v${PV}"/*-{apl,glk}*

	# Install all GeminiLake topology files.
	insinto /lib/firmware/intel/sof-tplg
	doins "sof-tplg-v${PV}"/*-glk*
}
