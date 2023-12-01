# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
PYTHON_COMPAT=( python3_{6..9} )

inherit distutils-r1

DESCRIPTION="Search for matches with a keyword tree"
HOMEPAGE="https://github.com/WojciechMula/pyahocorasick"
SRC_URI="mirror://pypi/${P:0:1}/${PN}/${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

PATCHES=(
	"${FILESDIR}/${P}-bytes.patch"
)
