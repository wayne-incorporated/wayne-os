# Copyright 1999-2018 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit autotools toolchain-funcs

DESCRIPTION="rpcsvc protocol definitions from glibc"
HOMEPAGE="https://github.com/thkukuk/rpcsvc-proto"
SRC_URI="https://github.com/thkukuk/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"

SLOT="0"
LICENSE="LGPL-2.1+ BSD"
KEYWORDS="*"
IUSE=""

RDEPEND="!<sys-libs/glibc-2.26"

src_prepare(){
	default
	eapply "${FILESDIR}"/${P}-old-preprocessor.patch #650852
	eapply "${FILESDIR}"/${P}-cross-compile.patch #crbug.com/898516

	# Use ${CHOST}-cpp, not 'cpp': bug #718138
	# Ideally we should use @CPP@ but rpcgen makes it hard to use '${CHOST}-gcc -E'
	sed -i -s "s/CPP = \"\/lib\/cpp\";/CPP = \"${CHOST}-cpp\";/" rpcgen/rpc_main.c || die
	eautoreconf
}

src_install(){
	default

	# provided by sys-fs/quota[rpc]
	rm "${ED%/}"/usr/include/rpcsvc/rquota.{x,h} || die
}
