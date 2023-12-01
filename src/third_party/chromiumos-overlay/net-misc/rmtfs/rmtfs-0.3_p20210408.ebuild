# Copyright 1999-2021 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-sanitizers user

DESCRIPTION="QMI Remote File System Server"
HOMEPAGE="https://github.com/andersson/rmtfs"
GIT_SHA1="293ab8babb27ac0f24247bb101fed9420c629c29"
SRC_URI="https://github.com/andersson/rmtfs/archive/${GIT_SHA1}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="asan +seccomp"

DEPEND="
	net-libs/libqrtr:=
	virtual/udev:=
"

RDEPEND="${DEPEND}"

S="${WORKDIR}/${PN}-${GIT_SHA1}"

PATCHES=(
	"${FILESDIR}/patches/0001-Use-fdatasync-instead-of-O_SYNC-on-storage.patch"
)

src_configure() {
	sanitizers-setup-env
}

src_install() {
	emake DESTDIR="${D}" prefix="${EPREFIX}/usr" install

	insinto /etc/init
	doins "${FILESDIR}/rmtfs.conf"
	doins "${FILESDIR}/check-rmtfs-early.conf"
	insinto /lib/udev/rules.d
	doins "${FILESDIR}/77-rmtfs.rules"

	# Install seccomp policy file.
	insinto /usr/share/policy
	use seccomp && newins "${FILESDIR}/rmtfs-seccomp-${ARCH}.policy" rmtfs-seccomp.policy
}

pkg_preinst() {
	enewgroup "rmtfs"
	enewuser "rmtfs"
}
