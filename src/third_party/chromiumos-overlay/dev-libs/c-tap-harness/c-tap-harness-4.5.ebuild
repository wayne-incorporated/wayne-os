# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit toolchain-funcs

DESCRIPTION="Pure C harness for the Test Anything Protocol"
HOMEPAGE="https://www.eyrie.org/~eagle/software/c-tap-harness/"
SRC_URI="https://archives.eyrie.org/software/devel/${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

src_configure() {
	tc-export CC LD AR RANLIB
	econf
}

src_install() {
	dobin tests/runtests
}
