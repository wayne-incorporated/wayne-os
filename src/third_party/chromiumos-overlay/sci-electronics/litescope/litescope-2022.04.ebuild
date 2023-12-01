# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
DISTUTILS_USE_SETUPTOOLS=rdepend
inherit distutils-r1

DESCRIPTION="LiteScope provides a small footprint and configurable Logic Analyzer core."
HOMEPAGE="https://github.com/enjoy-digital/litescope"

SRC_URI="https://github.com/enjoy-digital/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	sci-electronics/litex[${PYTHON_USEDEP}]
	sci-electronics/migen[${PYTHON_USEDEP}]
"

distutils_enable_tests unittest

src_test() {
	# Requires 'litex_boards' module.
	mv test/{,skipped-}test_examples.py

	distutils-r1_src_test
}
