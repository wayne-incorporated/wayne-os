# Copyright 1999-2015 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI="5"

inherit toolchain-funcs eutils

MY_P="policycoreutils-${PV}"

MY_RELEASEDATE="20170804"
SELNX_VER="${PV}"
SEPOL_VER="${PV}"

IUSE="audit"

# This package installs just the restorecon binary from policycoreutils,
# avoiding the need for dependencies that the full policycoreutils pulls in.
DESCRIPTION="SELinux restorecon utility"
HOMEPAGE="https://github.com/SELinuxProject/selinux/wiki"
SRC_URI="https://raw.githubusercontent.com/wiki/SELinuxProject/selinux/files/releases/${MY_RELEASEDATE}/${MY_P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"

DEPEND=">=sys-libs/libselinux-${SELNX_VER}:=
	>=sys-libs/glibc-2.4
	>=sys-libs/libsepol-${SEPOL_VER}:=
	audit? ( >=sys-process/audit-1.5.1 )"

RDEPEND="${DEPEND} !sys-apps/policycoreutils"

S="${WORKDIR}/${MY_P}"

src_prepare() {
	epatch_user
}

src_compile() {
	emake -C setfiles restorecon \
		AUDITH="$(usex audit)" \
		DESTDIR="${EROOT}" \
		CC="$(tc-getCC)"
}

src_install() {
	epatch "${FILESDIR}/0020-disable-autodetection-of-pam-and-audit.patch"
	emake -C setfiles restorecon DESTDIR="${D}" install
}
