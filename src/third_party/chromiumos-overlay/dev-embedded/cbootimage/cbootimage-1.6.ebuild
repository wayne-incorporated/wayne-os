# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=4

SRC_URI="http://github.com/NVIDIA/cbootimage/archive/v${PV}.tar.gz -> ${P}.tar.gz"

inherit autotools

DESCRIPTION="Utility for signing Tegra boot images"
HOMEPAGE="http://github.com/NVIDIA/cbootimage/"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="amd64 arm x86"
IUSE=""

src_prepare() {
	eautoreconf
}

src_install() {
	dobin src/cbootimage src/bct_dump
}
