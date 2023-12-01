# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Logitech Rally firmware"
SRC_URI="https://s3.amazonaws.com/chromiumos/rally-bin/${P}.tar.gz"

LICENSE="BSD-Logitech"
SLOT="0"
KEYWORDS="*"

RDEPEND="sys-apps/logitech-updater"
DEPEND=""

S="${WORKDIR}"

src_install() {
	insinto /lib/firmware/logitech/rally
	doins "tablehub.bin"
	doins "tablehub.bin.sig"
	doins "versions.bin"
	doins "versions.bin.sig"
}
