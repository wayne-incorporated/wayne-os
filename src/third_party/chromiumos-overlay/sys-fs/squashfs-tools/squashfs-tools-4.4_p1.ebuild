# Copyright 1999-2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
inherit flag-o-matic toolchain-funcs

MY_P=${P/_p/-git.}
DESCRIPTION="tools to create and extract Squashfs filesystems"
HOMEPAGE="https://github.com/plougher/squashfs-tools/"
SRC_URI="
	https://github.com/plougher/squashfs-tools/archive/${PV/_p/-git.}.tar.gz
		-> ${MY_P}.tar.gz"
S=${WORKDIR}/${MY_P}

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE="debug lz4 lzma lzo selinux xattr zstd"
REQUIRED_USE="selinux? ( xattr )"

RDEPEND="
	sys-libs/zlib
	lz4? ( app-arch/lz4 )
	lzma? ( app-arch/xz-utils )
	lzo? ( dev-libs/lzo )
	xattr? (
		selinux? ( sys-libs/libselinux )
		sys-apps/attr
	)
	zstd? ( app-arch/zstd )
"
DEPEND="${RDEPEND}"

#S="${WORKDIR}/squashfs${PV}/${PN}"

src_prepare() {
	eapply "${FILESDIR}"/${P}-file-map.patch
	eapply "${FILESDIR}"/${P}-4k-align.patch
	eapply "${FILESDIR}"/${P}-selinux.patch
	eapply_user
}

use10() { usex "${1}" 1 0; }

src_configure() {
	# set up make command line variables in EMAKE_SQUASHFS_CONF
	EMAKE_SQUASHFS_CONF=(
		LZMA_XZ_SUPPORT=$(use10 lzma)
		LZO_SUPPORT=$(use10 lzo)
		LZ4_SUPPORT=$(use10 lz4)
		SELINUX_SUPPORT=$(use10 selinux)
		XATTR_SUPPORT=$(use10 xattr)
		XZ_SUPPORT=$(use10 lzma)
		ZSTD_SUPPORT=$(use10 zstd)
	)

	tc-export CC
	use debug && append-cppflags -DSQUASHFS_TRACE
}

src_compile() {
	emake "${EMAKE_SQUASHFS_CONF[@]}" -C squashfs-tools
}

src_install() {
	dobin squashfs-tools/{mksquashfs,unsquashfs}
	dodoc ACKNOWLEDGEMENTS CHANGES README*
	dodoc -r RELEASE-READMEs
}
