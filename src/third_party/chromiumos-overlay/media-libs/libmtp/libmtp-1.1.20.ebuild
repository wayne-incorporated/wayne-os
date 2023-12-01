# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit autotools cros-sanitizers

DESCRIPTION="An implementation of Microsoft's Media Transfer Protocol (MTP)."
HOMEPAGE="http://libmtp.sourceforge.net/"
SRC_URI="mirror://sourceforge/${PN}/${P}.tar.gz"

LICENSE="LGPL-2.1"
SLOT="0"
KEYWORDS="*"
IUSE="-asan +crypt doc examples static-libs"

RDEPEND="virtual/libusb:1
	crypt? ( dev-libs/libgcrypt )"
DEPEND="${RDEPEND}
	virtual/pkgconfig
	doc? ( app-doc/doxygen )"

DOCS="AUTHORS ChangeLog README TODO"

PATCHES=(
	"${FILESDIR}"/${P}-00_disable_playlist.patch
	"${FILESDIR}"/${P}-01_build_fixes.patch
	"${FILESDIR}"/${P}-03_enable_ptp_support.patch
	"${FILESDIR}"/${P}-05_improve_warning_formatting.patch
	"${FILESDIR}"/${P}-06_disable_ptp_canon_eos_setdevicepropvalue.patch
	"${FILESDIR}"/${P}-09_do_not_build_udev_and_examples.patch
	"${FILESDIR}"/${P}-10_remove_nexus_s_from_device_list.patch
	"${FILESDIR}"/${P}-15_read_chunks.patch
	"${FILESDIR}"/${P}-19_raw_read_directory.patch
	"${FILESDIR}"/${P}-20_get_thumbnail_format.patch
	"${FILESDIR}"/${P}-22_ptp_timezone.patch
	"${FILESDIR}"/${P}-23_check_ptp_init_send_memory_handler_return.patch
	"${FILESDIR}"/${P}-24_update_ptp_ucs2str_reader.patch
)

src_prepare() {
	epatch "${PATCHES[@]}"
	eautoreconf
}

src_configure() {
	sanitizers-setup-env
	local myeconfargs=(
		$(use_enable static-libs static)
		$(use_enable doc doxygen)
		$(use_enable crypt mtpz)
	)
	econf "${myeconfargs[@]}"
}

src_install() {
	default
	find "${ED}" -name '*.la' -exec rm -f {} +

	if use examples; then
		docinto examples
		dodoc examples/*.{c,h,sh}
	fi
}
