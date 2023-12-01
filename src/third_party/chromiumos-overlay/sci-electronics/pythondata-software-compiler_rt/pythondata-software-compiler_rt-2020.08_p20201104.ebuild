# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# python_requires='>=3.5'
PYTHON_COMPAT=( python3_{6..9} )
inherit distutils-r1

DESCRIPTION="Python module containing data files for LLVM Compiler RT Module software."
HOMEPAGE="https://github.com/litex-hub/pythondata-software-compiler_rt"

GIT_REV="fcb03245613ccf3079cc833a701f13d0beaae09d"
SRC_URI="https://github.com/litex-hub/${PN}/archive/${GIT_REV}.tar.gz -> ${PN}-${GIT_REV}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}/${PN}-${GIT_REV}"

python_test() {
	"${EPYTHON}" test.py || die "Tests fail with ${EPYTHON}"
}
