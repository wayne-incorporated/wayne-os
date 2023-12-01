# Copyright 1999-2015 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7
inherit autotools eutils udev

DESCRIPTION="Separate utilities ebuild from upstream v4l-utils package"
HOMEPAGE="http://git.linuxtv.org/v4l-utils.git"
SRC_URI="http://linuxtv.org/downloads/v4l-utils/${P}.tar.bz2"

LICENSE="GPL-2+ LGPL-2.1+"
SLOT="0"
KEYWORDS="*"
IUSE="qt4 udev"

RDEPEND=">=media-libs/libv4l-${PV}
	qt4? (
		dev-qt/qtgui:4
		dev-qt/qtopengl:4
		virtual/opengl
		media-libs/alsa-lib
	)
	udev? ( virtual/libudev )
	!media-tv/v4l2-ctl
	!<media-tv/ivtv-utils-1.4.0-r2"
DEPEND="${RDEPEND}
	sys-devel/gettext
	virtual/pkgconfig"

PATCHES=(
	"${FILESDIR}"/${PN}-1.22.1-clang-fixes.patch
	"${FILESDIR}"/${PN}-1.24.1-Enable-large-file-support-flags.patch
)

src_prepare() {
	default
	eautoreconf
}

src_configure() {
	# v4l2-tracer uses exceptions, so they need to be enabled.
	cros_enable_cxx_exceptions

	# Hard disable the flags that apply only to the libs.
	econf \
		--disable-static \
		$(use_enable qt4 qv4l2) \
		$(use_with udev) \
		--with-udevdir="$(get_udevdir)" \
		--without-jpeg \
		--disable-bpf
}

src_install() {
	emake -C utils DESTDIR="${D}" install
	emake -C contrib DESTDIR="${D}" install

	dodoc README.md
	newdoc utils/libv4l2util/TODO TODO.libv4l2util
	newdoc utils/libmedia_dev/README README.libmedia_dev
	newdoc utils/dvb/README README.dvb
	newdoc utils/v4l2-compliance/fixme.txt fixme.txt.v4l2-compliance
}
