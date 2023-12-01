# Copyright 1999-2020 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-sanitizers user

DESCRIPTION="Qualcomm modem data service"
HOMEPAGE="https://source.codeaurora.org/quic/dataservices/modem-data-manager/log/?h=LC.UM.1.0"
#GIT_SHA1="79b2cf0d959b77f760cb5959007394bd2d3ab24b"
SRC_URI="https://source.codeaurora.org/quic/dataservices/modem-data-manager/log/?h=LC.UM.1.0 -> ${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="asan +seccomp"

DEPEND="net-libs/librmnetctl
	net-libs/libqrtr
"

RDEPEND="${DEPEND}"

S="${WORKDIR}/modem-data-manager"

src_configure() {
	sanitizers-setup-env
}

src_install() {
	emake DESTDIR="${D}" prefix="${EPREFIX}/usr" install

	insinto /etc/init
	doins "${FILESDIR}/qc-netmgr.conf"
}
