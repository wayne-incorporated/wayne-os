# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake-utils

DESCRIPTION="Library for interfacing with IIO devices"
HOMEPAGE="https://github.com/analogdevicesinc/libiio"
if [[ "${PV}" == "99999999" ]]; then
	EGIT_REPO_URI="https://github.com/analogdevicesinc/libiio"
	inherit git-r3
else
	SRC_URI="https://github.com/analogdevicesinc/${PN}/archive/v${PV}.tar.gz -> ${P}.tar.gz"
fi

KEYWORDS="*"
LICENSE="LGPL-2.1"
SLOT="0/${PV}"

# By default, only libiio is installed.
# For testing, use USE=libiio_all to compile tests and iiod daemon.
IUSE="aio debug iioservice libiio_all zeroconf"

RDEPEND="dev-libs/libxml2:=
	aio? ( dev-libs/libaio )
	libiio_all? (
		zeroconf? ( net-dns/avahi )
	)
	!dev-libs/libiio"

DEPEND="${RDEPEND}"

src_prepare() {
	use iioservice || eapply "${FILESDIR}"/${PN}-cros-ec-ring-workaround.patch

	eapply "${FILESDIR}"/${P}-illuminance.patch
	eapply "${FILESDIR}"/${P}-iio.h-Protect-against-inclusion-of-linux-iio-types.h.patch

	cmake-utils_src_prepare
	default
}

src_configure() {
	# network cmake section uses new cmake feature.
	mycmakeargs+=( -DWITH_NETWORK_BACKEND=OFF)
	use debug && mycmakeargs+=( -DLOG_LEVEL=Debug)
	use aio || mycmakeargs+=( -DWITH_AIO=OFF)
	# For test purposes, compile iiod and test tools, and allow connection over network.
	use libiio_all || mycmakeargs+=( -DWITH_IIOD=OFF -DWITH_TESTS=OFF)

	# Remove udev rules to detect sensors on USB devices, USB and serial backends.
	mycmakeargs+=( -DINSTALL_UDEV_RULE=OFF -DWITH_USB_BACKEND=OFF -DWITH_SERIAL_BACKEND=OFF)

	cmake-utils_src_configure
	default
}
