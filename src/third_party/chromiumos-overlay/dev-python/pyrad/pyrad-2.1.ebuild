# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

PYTHON_COMPAT=(python{3_6,3_7})

inherit distutils-r1

DESCRIPTION="Python implementation of a RADIUS client/server as described in RFC2865."
HOMEPAGE="https://github.com/pyradius/pyrad"
SRC_URI="mirror://pypi/${P:0:1}/${PN}/${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
	dev-python/netaddr[${PYTHON_USEDEP}]
	dev-python/six[${PYTHON_USEDEP}]
"
RDEPEND="${DEPEND}"
