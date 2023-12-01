# Copyright 1999-2019 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="X keyboard configuration database"
HOMEPAGE="https://www.freedesktop.org/wiki/Software/XKeyboardConfig https://gitlab.freedesktop.org/xkeyboard-config/xkeyboard-config"

if [[ ${PV} == 9999 ]]; then
	EGIT_REPO_URI="https://gitlab.freedesktop.org/xkeyboard-config/xkeyboard-config.git"
	inherit autotools git-r3
	# x11-misc/util-macros only required on live ebuilds
	LIVE_DEPEND=">=x11-misc/util-macros-1.18"
else
	SRC_URI="${XORG_BASE_INDIVIDUAL_URI}/data/${PN}/${P}.tar.bz2"
	KEYWORDS="*"
fi

LICENSE="MIT"
SLOT="0"
IUSE="cros_host"

RDEPEND="
	cros_host? ( !<x11-apps/xkbcomp-1.2.3 )
	!<x11-libs/libX11-1.4.3
"
DEPEND="
	dev-util/intltool
	sys-devel/gettext
	virtual/pkgconfig
	${LIVE_DEPEND}
"

PATCHES=(
	"${FILESDIR}"/${P}-gb-colemak.patch
	"${FILESDIR}"/${P}-gb-dvorak-deadkey.patch
	"${FILESDIR}"/${P}-neo-capslock-remap.patch
	"${FILESDIR}"/${P}-disable-level5-lock.patch
	"${FILESDIR}"/${P}-remap-capslock.patch
	"${FILESDIR}"/${P}-add-f19-24.patch
	"${FILESDIR}"/${P}-gb-extd-deadkey.patch
	"${FILESDIR}"/${P}-br-euro-degree.patch
	"${FILESDIR}"/${P}-es-euro-sign.patch
	"${FILESDIR}"/${P}-us-intl-pc.patch
	"${FILESDIR}"/${P}-bg-101.patch
	"${FILESDIR}"/${P}-jp-default-layout.patch
	"${FILESDIR}"/${P}-hr.patch
	"${FILESDIR}"/${P}-ee.patch
	"${FILESDIR}"/${P}-latam.patch
	"${FILESDIR}"/${P}-ch.patch
	"${FILESDIR}"/${P}-si.patch
)

src_prepare() {
	default
	[[ ${PV} == 9999 ]] && eautoreconf
}

src_configure() {
	local econfargs=(
		--with-xkb-base="${EPREFIX}/usr/share/X11/xkb"
		--enable-compat-rules
		# do not check for runtime deps
		--disable-runtime-deps
		--with-xkb-rules-symlink=xorg
	)

	econf "${econfargs[@]}"
}
