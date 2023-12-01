# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=4

inherit autotools

DESCRIPTION="Utility for downloading code to tegra system in recovery mode"
HOMEPAGE="http://github.com/NVIDIA/tegrarcm/"
SRC_URI="https://github.com/NVIDIA/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND=">=dev-libs/crypto++-5.6
	virtual/libusb:1"
DEPEND="${RDEPEND}
	virtual/pkgconfig"

src_prepare() {
	eautoreconf
}

src_install() {
	dobin src/tegrarcm
}
