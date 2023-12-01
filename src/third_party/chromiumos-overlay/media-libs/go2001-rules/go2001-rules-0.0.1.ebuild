# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit udev

DESCRIPTION="Rules for setting up /dev/ nodes for the go2001 video codec"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND="!media-libs/media-rules"
RDEPEND="virtual/udev"

# Because this ebuild has no source package, "${S}" doesn't get
# automatically created.  The compile phase depends on "${S}" to
# exist, so we make sure "${S}" refers to a real directory.
#
# The problem is apparently an undocumented feature of EAPI 4;
# earlier versions of EAPI don't require this.
S="${WORKDIR}"

src_install() {
	udev_dorules "${FILESDIR}"/50-go2001.rules
	insinto /etc/init
	doins "${FILESDIR}"/udev-trigger-codec.conf
}
