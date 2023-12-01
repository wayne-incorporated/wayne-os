# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=4

DESCRIPTION="GO2001 codec firmware"
HOMEPAGE="http://www.chromium.org/"
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/${P}.tar.bz2"

LICENSE="Google-TOS"
SLOT="0"
KEYWORDS="-* amd64"
IUSE=""

S="${WORKDIR}"

src_install() {
	insinto /lib/firmware
	doins go2001-boot.fw
	doins go2001.fw
}
