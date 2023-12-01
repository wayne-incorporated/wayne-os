# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# python_requires='>=3.5'
PYTHON_COMPAT=( python3_{6..9} )
inherit distutils-r1

DESCRIPTION="Python module containing verilog files for VexRISCV cpu."
HOMEPAGE="https://github.com/litex-hub/pythondata-cpu-vexriscv"

# Not on a master branch.
GIT_REV="9f85993307e913719381223ade365fdc0b477d2e"
SRC_URI="https://github.com/litex-hub/${PN}/archive/${GIT_REV}.tar.gz -> ${PN}-${GIT_REV}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}/${PN}-${GIT_REV}"

python_test() {
	"${EPYTHON}" test.py || die "Tests fail with ${EPYTHON}"
}
