# Copyright 1999-2019 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="exFAT filesystem FUSE module"
HOMEPAGE="https://github.com/relan/exfat"
SRC_URI="https://github.com/relan/exfat/releases/download/v${PV}/${P}.tar.gz"

# COPYING is GPL-2 but ChangeLog says "Relicensed the project from GPLv3+ to GPLv2+"
LICENSE="GPL-2+"
SLOT="0"
KEYWORDS="*"

RDEPEND="sys-fs/fuse:0"
DEPEND="${RDEPEND}
	virtual/pkgconfig"

PATCHES=(
	"${FILESDIR}/${PN}-1.3.0-timezone-offsets.patch"
)

src_install() {
	default
	dosym mount.exfat-fuse.8 /usr/share/man/man8/mount.exfat.8
}
