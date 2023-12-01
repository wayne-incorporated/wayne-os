# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
PYTHON_COMPAT=( python3_{6..9} )

inherit distutils-r1

DESCRIPTION="FTDI device driver written in pure Python"
HOMEPAGE="https://github.com/eblot/pyftdi"
SRC_URI="mirror://pypi/${P:0:1}/${PN}/${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
