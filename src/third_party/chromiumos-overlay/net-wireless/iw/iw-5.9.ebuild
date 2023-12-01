# Copyright 1999-2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit toolchain-funcs

DESCRIPTION="nl80211 configuration utility for wireless devices using the mac80211 stack"
HOMEPAGE="https://wireless.wiki.kernel.org/en/users/Documentation/iw"
SRC_URI="https://www.kernel.org/pub/software/network/${PN}/${P}.tar.xz"

LICENSE="ISC"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="dev-libs/libnl:="
DEPEND="${RDEPEND}"
BDEPEND="virtual/pkgconfig"

# TODO(b/261113528): Uprev iw command to 5.19
PATCHES=(
	"${FILESDIR}/${PN}-5.9-iw-handle-positive-error-codes-gracefully.patch"
	"${FILESDIR}/${PN}-5.9-iw-scan-add-extension-tag-parsing.patch"
	"${FILESDIR}/${PN}-5.9-iw-util-factor-out-HE-capability-parser.patch"
	"${FILESDIR}/${PN}-5.9-iw-scan-parse-HE-capabilities.patch"
	"${FILESDIR}/${PN}-5.9-iw-scan-fixup-HE-caps-whitespace.patch"
	"${FILESDIR}/${PN}-5.9-iw-retain___stop___cmd.patch"
	"${FILESDIR}/${PN}-5.9-iw-Add-coloc-and-flush-options-to-sched_scan.patch"
	"${FILESDIR}/${PN}-5.9-iw-scan-add-flag-for-scanning-colocated-ap.patch"
)

src_prepare() {
	default
	tc-export CC LD PKG_CONFIG

	# do not compress man pages by default.
	sed 's@\(iw\.8\)\.gz@\1@' -i Makefile || die
}

src_compile() {
	CFLAGS="${CFLAGS} ${CPPFLAGS}"
	LDFLAGS="${CFLAGS} ${LDFLAGS}" \
	emake V=1
}

src_install() {
	emake V=1 DESTDIR="${D}" PREFIX="${EPREFIX}/usr" install
}
