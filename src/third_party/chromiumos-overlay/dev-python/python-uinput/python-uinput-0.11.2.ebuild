# Copyright 1999-2014 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/dev-python/python-uinput/python-uinput-0.10.2.ebuild,v 1.1 2014/07/28 07:05:21 jlec Exp $

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )

inherit distutils-r1

DESCRIPTION="Pythonic API to the Linux uinput kernel module"
HOMEPAGE="http://tjjr.fi/sw/python-uinput/"
SRC_URI="mirror://pypi/${P:0:1}/${PN}/${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
	${PYTHON_DEPS}
	virtual/udev
"
RDEPEND="${DEPEND}"

python_prepare_all() {
	rm libsuinput/src/libudev.h || die
	cp "${FILESDIR}/"*.py src/ || die
	distutils-r1_python_prepare_all
}
