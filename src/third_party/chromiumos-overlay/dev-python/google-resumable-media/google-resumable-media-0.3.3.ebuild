# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=6

PYTHON_COMPAT=( python3_{6..9} )

inherit distutils-r1

DESCRIPTION="Utilities for Google Media Downloads and Resumable Uploads"
HOMEPAGE="https://pypi.python.org/pypi/google-resumable-media"
SRC_URI="mirror://pypi/${PN:0:1}/${PN}/${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
RDEPEND=">=dev-python/requests-2.18.0[${PYTHON_USEDEP}]
	dev-python/six[${PYTHON_USEDEP}]"
DEPEND="${RDEPEND}
	dev-python/setuptools[${PYTHON_USEDEP}]"
