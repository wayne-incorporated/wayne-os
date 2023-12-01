# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# python_requires='>=3.5'
PYTHON_COMPAT=( python3_{6..9} )
inherit distutils-r1

DESCRIPTION="Python module containing data files for Ethernet TAP Config misc."
HOMEPAGE="https://github.com/litex-hub/pythondata-misc-tapcfg"

GIT_REV="0e6809132b7a42d26fc148b2b5e54ede8d6021ab"
SRC_URI="https://github.com/litex-hub/${PN}/archive/${GIT_REV}.tar.gz -> ${PN}-${GIT_REV}.tar.gz"

LICENSE="LGPL-2.1"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}/${PN}-${GIT_REV}"

python_test() {
	"${EPYTHON}" test.py || die "Tests fail with ${EPYTHON}"
}
