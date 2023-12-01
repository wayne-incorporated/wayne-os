# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6
inherit flag-o-matic toolchain-funcs

DESCRIPTION="Block tests suite"
HOMEPAGE="https://github.com/osandov/blktests"
GIT_REV="0ee7ebae6324a173fc3ac0d994e810bf4817ee70"
SRC_URI="https://github.com/osandov/blktests/archive/${GIT_REV}.tar.gz -> ${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE="static"

DEPEND=""

PATCHES=(
	"${FILESDIR}/blktests-20190430-Remove-unnecessary-linux-kvm.h-include.patch"
)

RDEPEND="sys-fs/e2fsprogs
	sys-block/blktrace
	sys-block/fio
	sys-fs/xfsprogs
"

S="${WORKDIR}/${PN}-${GIT_REV}/"

src_configure() {
	use static && append-ldflags -static
	tc-export CC
	export prefix=/usr/local
}
