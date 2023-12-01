# Copyright 1999-2020 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

MY_PN="intel-vaapi-driver"

inherit autotools multilib-minimal

DESCRIPTION="HW video decode support for Intel integrated graphics"
HOMEPAGE="https://github.com/intel/intel-vaapi-driver"
SRC_URI="https://github.com/intel/${MY_PN}/releases/download/${PV}/${MY_PN}-${PV}.tar.bz2"
S="${WORKDIR}/${MY_PN}-${PV}"
KEYWORDS="*"
LICENSE="MIT"
SLOT="0"
IUSE="hybrid_codec"
RESTRICT="test" # No tests

RDEPEND="
	>=x11-libs/libdrm-2.4.52[video_cards_intel,${MULTILIB_USEDEP}]
	>=x11-libs/libva-2.4.0:=[${MULTILIB_USEDEP}]
	hybrid_codec? ( media-libs/intel-hybrid-driver[${MULTILIB_USEDEP}] )
"
DEPEND="${RDEPEND}"
BDEPEND="virtual/pkgconfig"

src_prepare() {
	eapply "${FILESDIR}"/no_explicit_sync_in_va_sync_surface.patch
	eapply "${FILESDIR}"/Avoid-GPU-crash-with-malformed-streams.patch
	eapply "${FILESDIR}"/set_multisample_state_for_gen6.patch
	eapply "${FILESDIR}"/0001-Remove-blitter-usage-from-driver.patch
	eapply "${FILESDIR}"/Handle-the-odd-resolution.patch
	eapply "${FILESDIR}"/0002-Fix-VP9.2-config-verification.patch
	eapply "${FILESDIR}"/0003-FROMGIT-FROMLIST-i965_device_info.c-Add-missing-entr.patch
	eapply_user
	sed -e 's/intel-gen4asm/\0diSaBlEd/g' -i configure.ac || die
	eautoreconf
}

multilib_src_configure() {
	local myconf=(
		--disable-wayland
		--disable-x11
		"$(use_enable hybrid_codec)"
	)
	ECONF_SOURCE="${S}" econf "${myconf[@]}"
}

multilib_src_install_all() {
	find "${D}" -name "*.la" -delete || die
}
