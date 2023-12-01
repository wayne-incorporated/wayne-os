# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
DESCRIPTION="Pixart Touchpad utility tool for Firmware Update"
PROJ_NAME=pix_tpfwup
HOMEPAGE="https://github.com/PixArt-Imaging-Inc/pix_tpfwup"
SRC_URI="https://github.com/PixArt-Imaging-Inc/${PROJ_NAME}/archive/v${PV}.tar.gz -> ${PROJ_NAME}-${PV}.tar.gz"
S="${WORKDIR}/${PROJ_NAME}-${PV}"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_install() {
	dosbin pixtpfwup
}
