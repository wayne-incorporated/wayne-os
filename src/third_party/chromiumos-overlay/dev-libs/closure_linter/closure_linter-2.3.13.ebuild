# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

PYTHON_COMPAT=( python3_{6..8} )
inherit distutils-r1

DESCRIPTION="A utility that checks JavaScript files for style issues"
HOMEPAGE="https://developers.google.com/closure/utilities/"
SRC_URI="http://closure-linter.googlecode.com/files/closure_linter-${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

DEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND=""
