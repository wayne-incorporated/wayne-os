# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

PYTHON_COMPAT=( python3_{6,7,8} )

inherit distutils-r1

DESCRIPTION="device for measuring latency of physical sensors and outputs on phones and computers"
HOMEPAGE="https://github.com/google/walt"
SRC_URI="https://github.com/google/walt/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="dev-python/numpy[${PYTHON_USEDEP}]"
DEPEND=""

S="${WORKDIR}/walt-${PV}/${PN}"
