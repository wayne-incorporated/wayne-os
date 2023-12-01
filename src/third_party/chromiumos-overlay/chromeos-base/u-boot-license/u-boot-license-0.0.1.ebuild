# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This ebuild exists to install a license file for U-Boot so that licenesing
# information will appear on the Chrome OS credits page.
EAPI=6

DESCRIPTION="Das U-Boot -- the Universal Boot Loader"
HOMEPAGE="https://www.denx.de/wiki/U-Boot"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

S=${WORKDIR}

src_install() {
	insinto /boot
	doins "${FILESDIR}/README.U-Boot"
}
