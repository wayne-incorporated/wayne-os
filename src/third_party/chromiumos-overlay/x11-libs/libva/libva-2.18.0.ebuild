# Copyright 1999-2022 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit autotools multilib-minimal

DESCRIPTION="Video Acceleration (VA) API for Linux"
HOMEPAGE="https://01.org/linuxmedia/vaapi"
SRC_URI="https://github.com/intel/libva/releases/download/${PV}/${P}.tar.gz"
KEYWORDS="*"
LICENSE="MIT"
SLOT="0/$(ver_cut 1)"
IUSE="utils intel_oemcrypto internal intel_ihd_pavp"

VIDEO_CARDS="i965 amdgpu iHD"
for x in ${VIDEO_CARDS}; do
	IUSE+=" video_cards_${x}"
done

RDEPEND="
	>=x11-libs/libdrm-2.4.60[${MULTILIB_USEDEP}]
"
DEPEND="${RDEPEND}"
BDEPEND="
	virtual/pkgconfig
"
PDEPEND="
	video_cards_i965? ( >=x11-libs/libva-intel-driver-2.0.0[${MULTILIB_USEDEP}] )
	video_cards_iHD? (
		intel_oemcrypto? (
			internal? ( x11-libs/libva-intel-media-driver-pavp[${MULTILIB_USEDEP}] )
			!internal? (
				intel_ihd_pavp? ( x11-libs/libva-intel-media-driver-pavp[${MULTILIB_USEDEP}] )
				!intel_ihd_pavp? ( ~x11-libs/libva-intel-media-driver-23.1.6[${MULTILIB_USEDEP}] )
			)
		)
		!intel_oemcrypto? ( ~x11-libs/libva-intel-media-driver-23.1.6[${MULTILIB_USEDEP}] )
	)
	video_cards_amdgpu? ( virtual/opengles[${MULTILIB_USEDEP}] )
	utils? ( media-video/libva-utils )
"

DOCS=( NEWS )

MULTILIB_WRAPPED_HEADERS=(
/usr/include/va/va_backend_glx.h
/usr/include/va/va_x11.h
/usr/include/va/va_dri2.h
/usr/include/va/va_dricommon.h
/usr/include/va/va_glx.h
)

src_prepare() {
	default
	eautoreconf
}

multilib_src_configure() {
	local myeconfargs=(
		--with-drivers-path="${EPREFIX}/usr/$(get_libdir)/va/drivers"
		--enable-drm
		--disable-x11
		--disable-glx
		--disable-wayland
		--enable-va-messaging
	)
	ECONF_SOURCE="${S}" econf "${myeconfargs[@]}"
}

multilib_src_install_all() {
	default
	find "${ED}" -type f -name "*.la" -delete || die
}
