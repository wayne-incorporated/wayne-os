# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

CROS_WORKON_PROJECT="chromiumos/third_party/kernel"
CROS_WORKON_LOCALNAME="kernel/v4.19"
CROS_WORKON_EGIT_BRANCH="chromeos-4.19"
CROS_WORKON_SUBTREE="tools/usb/usbip"

inherit autotools cros-workon eutils cros-sanitizers

DESCRIPTION="Userspace utilities for a general USB device sharing system over IP networks"
HOMEPAGE="https://www.kernel.org/"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~*"
IUSE="static-libs tcpd"
RESTRICT=""

RDEPEND=">=dev-libs/glib-2.6
	sys-apps/hwdata
	>=sys-kernel/linux-headers-3.17
	virtual/libudev
	tcpd? ( sys-apps/tcp-wrappers )"
DEPEND="${RDEPEND}
	virtual/pkgconfig"

DOCS="AUTHORS README"

S=${WORKDIR}/linux-${PV}/tools/usb/${PN}

src_unpack() {
	cros-workon_src_unpack
	S+="/tools/usb/usbip"
}

src_prepare() {
	# remove -Werror from build, bug #545398
	sed -i 's/-Werror[^ ]* //g' configure.ac || die

	default

	eautoreconf
}

src_configure() {
	sanitizers-setup-env

	econf \
		$(use_enable static-libs static) \
		"$(use_with tcpd tcp-wrappers)" \
		--with-usbids-dir=/usr/share/hwdata
}

src_install() {
	default
	prune_libtool_files
}
