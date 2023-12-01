# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="4"
CROS_WORKON_COMMIT="a1d938f8b4253c76fb31e69de33266cb71bda141"
CROS_WORKON_TREE="e974868edf39e05cf8c1230fc0bdaf6e928f6922"
CROS_WORKON_PROJECT="chromiumos/third_party/em100"

inherit cros-workon toolchain-funcs

DESCRIPTION="A simple utility to control a Dediprog EM100pro from Linux"
SRC_URI=""

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"

DEPEND="virtual/libusb:1"
RDEPEND="${DEPEND}"

src_compile() {
	tc-export CC PKG_CONFIG

	emake
}

src_install() {
	dosbin em100
}
