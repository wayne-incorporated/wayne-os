# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
DISTUTILS_USE_SETUPTOOLS=rdepend
inherit distutils-r1

DESCRIPTION="LiteEth provides a small footprint and configurable Ethernet core."
HOMEPAGE="https://github.com/enjoy-digital/liteeth"

SRC_URI="https://github.com/enjoy-digital/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	sci-electronics/liteiclink[${PYTHON_USEDEP}]
	sci-electronics/litex[${PYTHON_USEDEP}]
	sci-electronics/migen[${PYTHON_USEDEP}]
"

distutils_enable_tests unittest
