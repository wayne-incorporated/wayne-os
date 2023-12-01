# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
inherit toolchain-funcs

DESCRIPTION="A FW updating utility for Weida touchscreens"
PROJ_NAME="wdt_util_src"
GIT_TAG="wdt_util_v${PV}"
HOMEPAGE="https://github.com/chenhn123/wdt_util_src"
SRC_URI="https://github.com/chenhn123/wdt_util_src/archive/${GIT_TAG}.tar.gz -> ${P}.tar.gz"
S="${WORKDIR}/${PROJ_NAME}-${GIT_TAG}"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC
	append-lfs-flags
}

src_install() {
	dosbin wdt_util
}
