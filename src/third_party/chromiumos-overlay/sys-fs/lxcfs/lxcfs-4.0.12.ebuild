# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

# TODO(crbug.com/1097610) Once stabilized, this can go back to
# portage-stable

EAPI=7

inherit autotools flag-o-matic systemd verify-sig

DESCRIPTION="FUSE filesystem for LXC"
HOMEPAGE="https://linuxcontainers.org/lxcfs/introduction/ https://github.com/lxc/lxcfs/"
SRC_URI="https://linuxcontainers.org/downloads/lxcfs/${P}.tar.gz
	verify-sig? ( https://linuxcontainers.org/downloads/lxcfs/${P}.tar.gz.asc )"

LICENSE="Apache-2.0 LGPL-2+"
SLOT="4"
KEYWORDS="*"

# TODO(crbug.com/1097610) Upstream gentoo has lxcfs depending on fuse:3, but the
# actual configure script prefers fuse:0. This saves us from having to update
# fuse at least.
RDEPEND="sys-fs/fuse:0"
DEPEND="${RDEPEND}"
BDEPEND="sys-apps/help2man
	verify-sig? ( app-crypt/openpgp-keys-linuxcontainers )"

# Looks like these won't ever work in a container/chroot environment. #764620
RESTRICT="test"

VERIFY_SIG_OPENPGP_KEY_PATH=${BROOT}/usr/share/openpgp-keys/linuxcontainers.asc

src_prepare() {
	default
	eautoreconf
}

src_configure() {
	# Needed for x86 support, bug #819762
	# May be able to drop when/if ported to meson, but re-test w/ x86 chroot
	append-lfs-flags

	# Replace help2man for /bin/true to avoid issues when
	# cross-compiling (b/196492646)
	export ac_cv_path_HELP2MAN=/bin/true

	# Without the localstatedir the filesystem isn't mounted correctly
	# Without with-distro ./configure will fail when cross-compiling
	econf --localstatedir=/var --with-distro=gentoo --disable-static
}

src_test() {
	cd tests/ || die
	emake -j1 tests
	./main.sh || die "Tests failed"
}

src_install() {
	default

	newconfd "${FILESDIR}"/lxcfs-4.0.0.confd lxcfs
	newinitd "${FILESDIR}"/lxcfs-4.0.0.initd lxcfs

	find "${ED}" -name '*.la' -delete || die
}
