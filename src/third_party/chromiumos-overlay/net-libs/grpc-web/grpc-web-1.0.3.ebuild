# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=6

inherit flag-o-matic toolchain-funcs

DESCRIPTION="A plugin to protoc that generates typscript/javascript to access gRPC services"
HOMEPAGE="https://www.grpc.io"
SRC_URI="https://github.com/${PN}/${PN}/archive/v${MY_PV}.tar.gz -> ${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="dev-libs/protobuf:="
RDEPEND="${DEPEND}"

src_prepare() {
	# The makefile specifies the compiler to be g++, remove so we can use the default.
	sed -i 's:CXX =.*::g' ${WORKDIR}/${P}/javascript/net/grpc/web/Makefile || die
	default
}

src_compile() {
	emake \
		AR="$(tc-getAR)" \
		AROPTS="rcs" \
		CFLAGS="${CFLAGS}" \
		CXXFLAGS="${CXXFLAGS}" \
		LD="${CC}" \
		LDXX="${CXX}" \
		STRIP=/bin/true \
		plugin
}

src_install() {
	dobin ${WORKDIR}/${P}/javascript/net/grpc/web/protoc-gen-grpc-web
}
