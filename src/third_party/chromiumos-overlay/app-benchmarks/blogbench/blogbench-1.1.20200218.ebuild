# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit autotools toolchain-funcs

GIT_HASH="d000aaf9390100bb3024e6b4aed9d945256259d5"
DESCRIPTION="A portable filesystem benchmark that tries to reproduce the load
of a real-world busy file server"
HOMEPAGE="https://github.com/jedisct1/Blogbench"
SRC_URI="https://github.com/jedisct1/Blogbench/archive/${GIT_HASH}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

PATCHES=( "${FILESDIR}/${P}-snprintf.patch" )
S="${WORKDIR}/Blogbench-${GIT_HASH}"

src_prepare() {
	default

	eautoreconf
}

src_configure() {
	tc-export CC
	econf
}
