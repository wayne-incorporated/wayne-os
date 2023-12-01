# Copyright 2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
inherit toolchain-funcs

GIT_HASH="d21ec4132b419c8522f73baa3d95ef04cb1a0b90"
DESCRIPTION="Universal Flash Storage user space tooling for Linux"
HOMEPAGE="https://github.com/westerndigitalcorporation/ufs-utils"
SRC_URI="${HOMEPAGE}/archive/${GIT_HASH}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}/ufs-utils-${GIT_HASH}"

src_compile() {
	emake CC="$(tc-getCC)"
}

src_install() {
	dosbin ufs-utils
}
