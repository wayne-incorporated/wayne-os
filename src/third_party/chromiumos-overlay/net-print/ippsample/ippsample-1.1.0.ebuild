# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit toolchain-funcs cros-sanitizers

DESCRIPTION="ippsample print testing utility"
HOMEPAGE="https://github.com/istopwg/ippsample/blob/master/README.md"

LICENSE="Apache-2.0"

GIT_SHA1="df83ad39d54f05aab39dab013464bea3514034d6"
SRC_URI="https://github.com/istopwg/ippsample/archive/${GIT_SHA1}.zip -> ${P}.zip"

SLOT="0"
IUSE="+ssl +zeroconf"
KEYWORDS="*"

CDEPEND="
	ssl? (
		>=dev-libs/libgcrypt-1.5.3:=
		>=net-libs/gnutls-3.6.14:=
	)
	zeroconf? ( >=net-dns/avahi-0.8:= )
"

DEPEND="${CDEPEND}"

RDEPEND="${CDEPEND}"

PATCHES=(
	"${FILESDIR}/ippsample-1.0.0-do-not-force-local-BinDir-directory.patch"
	"${FILESDIR}/ippsample-1.1.0-use-PKG_CONFIG.patch"
)

S="${WORKDIR}/${PN}-${GIT_SHA1}"

src_configure() {

	sanitizers-setup-env

	tc-export PKG_CONFIG

	local myeconfargs=(
		--with-tls=gnutls \
		"$(use_with zeroconf dnssd avahi)" \
		--includedir=/usr/local/include
	)
	econf "${myeconfargs[@]}"
}

src_install() {
	# Disable install-sh stripping so we can rely on portage split debug.
	emake DESTDIR="${D}" STRIPPROG=true install

	# Install ippserver test prerequisites.
	insinto /usr/local/share/ippsample
	doins -r "${S}"/test
	# Installing libcups should be left to net-print/cups (b/193691589).
	rm "${D}/usr/$(get_libdir)/libcups.a" || die
}

src_test() {
	emake check
}
