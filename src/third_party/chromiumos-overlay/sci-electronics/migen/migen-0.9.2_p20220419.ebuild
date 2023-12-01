# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# setup.py: "You need Python 3.3+"
PYTHON_COMPAT=( python3_{6..9} )
inherit distutils-r1

DESCRIPTION="Python toolbox for building complex digital hardware."
HOMEPAGE="https://github.com/m-labs/migen"

GIT_REV="d4e3f34177c32f09904397179e6ed9c83175e528"
SRC_URI="https://github.com/m-labs/${PN}/archive/${GIT_REV}.tar.gz -> ${PN}-${GIT_REV}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	dev-python/colorama
"

S="${WORKDIR}/${PN}-${GIT_REV}"

distutils_enable_tests unittest
