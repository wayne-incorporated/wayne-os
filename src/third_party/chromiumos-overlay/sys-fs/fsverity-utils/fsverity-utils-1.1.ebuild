# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit linux-info

if [[ ${PV} == *9999* ]]; then
	EGIT_REPO_URI="https://git.kernel.org/pub/scm/fs/fsverity/fsverity-utils.git"
	inherit git-r3
	SRC_URI=""
else
	SRC_URI="https://git.kernel.org/pub/scm/linux/kernel/git/ebiggers/${PN}.git/snapshot/${P}.tar.gz"
	KEYWORDS="*"
fi

DESCRIPTION="Userspace utility for file-level integrity/authenticity verification"
HOMEPAGE="https://git.kernel.org/pub/scm/fs/fsverity/fsverity-utils.git"
LICENSE="GPL-2"
SLOT="0"

DEPEND="dev-libs/openssl:="

RDEPEND="${DEPEND}"

src_install() {
	dobin fsverity
}
