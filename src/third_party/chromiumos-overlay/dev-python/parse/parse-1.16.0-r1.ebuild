# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
PYTHON_COMPAT=( python3_{6..8} )

inherit distutils-r1

DESCRIPTION="Parse strings based on Python's format() syntax"
HOMEPAGE="https://github.com/r1chardj0n3s/parse"
GIT_SHA1="27db6b3498aeee80aa87c083dda76f2df2d87fa4"
SRC_URI="https://github.com/r1chardj0n3s/parse/archive/${GIT_SHA1}.zip -> ${P}.zip"
S="${WORKDIR}/${PN}-${GIT_SHA1}"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
