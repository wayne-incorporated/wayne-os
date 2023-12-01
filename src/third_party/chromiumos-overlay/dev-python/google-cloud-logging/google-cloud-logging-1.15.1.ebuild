# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

PYTHON_COMPAT=( python3_{6..8} pypy3 )

inherit distutils-r1

DESCRIPTION="Stackdriver Logging API client library"
HOMEPAGE="https://pypi.org/project/google-cloud-logging/"
SRC_URI="mirror://pypi/${PN:0:1}/${PN}/${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

RDEPEND="dev-python/google-api-core[${PYTHON_USEDEP}]
	dev-python/google-cloud-core[${PYTHON_USEDEP}]"
DEPEND="${RDEPEND}"
