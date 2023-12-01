# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit arc-build-constants tmpfiles

DESCRIPTION="Ureadahead - Read files in advance during boot"
HOMEPAGE="https://launchpad.net/ureadahead"
SRC_URI="https://launchpad.net/ureadahead/trunk/${PV}/+download/${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE="arcvm"

RDEPEND="
	sys-apps/util-linux
	>=sys-fs/e2fsprogs-1.41
	sys-libs/libnih
"
DEPEND="${RDEPEND}"
BDEPEND="
	sys-devel/gettext
"

PATCHES=(
	"${FILESDIR}"/${P}-11.patch   # Downloaded from upstream
	"${FILESDIR}"/${P}-13.patch   # Downloaded from upstream
	"${FILESDIR}"/${P}-container.patch
	"${FILESDIR}"/${P}-detect-rotational.patch
	"${FILESDIR}"/${P}-sysmacros.h
	"${FILESDIR}"/${P}-fileio-overflow.patch # crbug.com/216504
	"${FILESDIR}"/${P}-large-readahead.patch
	"${FILESDIR}"/${P}-pack-file-and-path-prefix-filter-options.patch
	"${FILESDIR}"/${P}-16.patch   # Downloaded from upstream
	"${FILESDIR}"/${P}-no-debug-tracing.patch
	"${FILESDIR}"/${P}-force-ssd-mode.patch
	"${FILESDIR}"/${P}-tracefs.patch
	"${FILESDIR}"/${P}-use-existing-trace-events.patch
)

src_configure() {
	econf --sbindir=/sbin
}

src_install() {
	default
	rm -r "${D}/etc/init"

	# install init script
	insinto /etc/init
	doins "${FILESDIR}"/init/*.conf

	dotmpfiles "${FILESDIR}"/tmpfiles.d/*

	# install executable into guest vendor image for ARCVM
	if use arcvm; then
		arc-build-constants-configure
		# shellcheck disable=SC2154 # Defined in arc-build-constants.eclass.
		exeinto "${ARC_VM_VENDOR_DIR}/bin"
		doexe "${WORKDIR}/${P}/src/ureadahead"
	fi
}
