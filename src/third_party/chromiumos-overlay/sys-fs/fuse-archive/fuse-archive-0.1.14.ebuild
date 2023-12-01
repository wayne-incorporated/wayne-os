# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Serve an archive or compressed file as a FUSE file system"
HOMEPAGE="https://github.com/google/fuse-archive"
SRC_URI="https://github.com/google/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	app-arch/libarchive:=
	sys-fs/fuse:0"
DEPEND="${RDEPEND}"
BDEPEND="virtual/pkgconfig"
