# Copyright 1999-2018 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6
inherit cros-sanitizers

DESCRIPTION="Fuse-filesystem utilizing the sftp service"
HOMEPAGE="https://github.com/libfuse/sshfs"
SRC_URI="https://github.com/libfuse/${PN}/releases/download/${P}/${P}.tar.gz"

LICENSE="GPL-2"
KEYWORDS="*"
SLOT="0"

CDEPEND=">=sys-fs/fuse-2.6.0_pre3:0
	>=dev-libs/glib-2.4.2"
RDEPEND="${CDEPEND}
	>=net-misc/openssh-4.4"
DEPEND="${CDEPEND}
	virtual/pkgconfig"

src_prepare() {
	eapply "${FILESDIR}"/sshfs-2.10-mount-mode.patch
	eapply "${FILESDIR}"/sshfs-2.10-disable-symlinks.patch
	eapply "${FILESDIR}"/sshfs-2.10-vsock.patch
	eapply_user
}

src_configure() {
	sanitizers-setup-env
	default
}
