# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit autotools

if [[ ${PV} == 9999 ]]; then
	EGIT_REPO_URI="git://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git"
	inherit git-r3
else
	SRC_URI="https://git.kernel.org/pub/scm/linux/kernel/git/xiang/${PN}.git/snapshot/${P}.tar.gz"
	KEYWORDS="*"
fi

DESCRIPTION="Userspace utilities for linux-erofs file system"
HOMEPAGE="https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git"

LICENSE="GPL-2"
SLOT="0"
IUSE="selinux"

RDEPEND="
	app-arch/lz4:=
	selinux? ( sys-libs/libselinux:= )
"
DEPEND="${RDEPEND}"

src_prepare() {
	default
	eautoreconf
}

src_configure() {
	econf $(use_with selinux)
}

src_install() {
	dobin mkfs/mkfs.erofs fsck/fsck.erofs dump/dump.erofs
}
