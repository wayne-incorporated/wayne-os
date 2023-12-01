# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit autotools eutils toolchain-funcs

GIT_HASH="ee51841e0d99d25ab18027770f6b6f0596a07574"
DESCRIPTION="A file system test suite that exercises POSIX system calls"
HOMEPAGE="https://github.com/pjd/pjdfstest"
SRC_URI="https://github.com/pjd/pjdfstest/archive/${GIT_HASH}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	dev-libs/c-tap-harness
	dev-libs/openssl
"

PATCHES=(
	"${FILESDIR}/${P}-fix-format-specifier.patch"
	"${FILESDIR}/${P}-remove-fixed-todos.patch"
)

S="${WORKDIR}/${PN}-${GIT_HASH}"

src_prepare() {
	default
	# This test passes on 64-bit hosts but not on 32-bit hosts.
	use amd64 || use arm64 || eapply "${FILESDIR}/${P}-fix-2038.patch"
	eautoreconf
}

src_configure() {
	tc-export CC
	econf
}

src_install() {
	exeinto /opt/pjdfstest/
	doexe pjdfstest

	insinto /opt/pjdfstest/
	doins -r tests

	# The test harness requires that the tests are executable.
	find "${D}/opt/pjdfstest/tests" -name '*.t' -exec chmod +x {} \;
}
