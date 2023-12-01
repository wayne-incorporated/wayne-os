# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )
inherit distutils-r1

DESCRIPTION="LiteICLink provides small footprint and configurable Inter-Chip
communication cores."
HOMEPAGE="https://github.com/enjoy-digital/liteiclink"

SRC_URI="https://github.com/enjoy-digital/${PN}/archive/${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	sci-electronics/litex[${PYTHON_USEDEP}]
	sci-electronics/migen[${PYTHON_USEDEP}]
"

distutils_enable_tests unittest
