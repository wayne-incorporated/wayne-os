# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit cros-sanitizers eutils autotools

DESCRIPTION="Epson Inkjet Printer Driver (ESC/P-R)"
HOMEPAGE="http://download.ebz.epson.net/dsc/search/01/search/?OSC=LX"
SRC_URI="https://download3.ebz.epson.net/dsc/f/03/00/14/34/76/47198c0bab357b96ec59490973c492c5d6059604/epson-inkjet-printer-escpr-1.7.25-1lsb3.2.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="net-print/cups"
RDEPEND="${DEPEND}"

PATCHES=(
	"${FILESDIR}/1.6.5-warnings.patch"
	"${FILESDIR}/${PN}-1.6.10-search-filter.patch"
	"${FILESDIR}/${PN}-1.7.6-cupsRasterHeader.patch"
	"${FILESDIR}/${PN}-1.7.25-lfs-support.patch"
)

src_prepare() {
	epatch "${PATCHES[@]}"
	epatch_user
	eautoreconf
}

src_configure() {
	sanitizers-setup-env
	econf \
		--disable-shared \
		--with-cupsfilterdir=/usr/libexec/cups/filter \
		--with-cupsppddir=/usr/share/cups

	# Makefile calls ls to generate a file list which is included in Makefile.am
	# Set the collation to C to avoid automake being called automatically
	unset LC_ALL
	export LC_COLLATE=C
}

src_install() {
	emake -C src DESTDIR="${D}" install
}
