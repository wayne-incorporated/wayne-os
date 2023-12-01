# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
EGIT_REPO_URI="https://gitlab.freedesktop.org/mesa/drm.git"
if [[ ${PV} != *9999* ]]; then
	CROS_WORKON_COMMIT="56f81e6776c1c100c3f627b2c1feb9dcae2aad3c"
	CROS_WORKON_TREE="f2dad5f135f56bf9e56b44d5b9637ffb59d38f23"
fi
CROS_WORKON_PROJECT="chromiumos/third_party/libdrm"
CROS_WORKON_LOCALNAME="libdrm"
CROS_WORKON_EGIT_BRANCH="chromeos-2.4.106"
CROS_WORKON_MANUAL_UPREV="1"

P=${P#"arc-"}
PN=${PN#"arc-"}
S="${WORKDIR}/${P}"

inherit cros-workon arc-build meson multilib-minimal

DESCRIPTION="X.Org libdrm library"
HOMEPAGE="http://dri.freedesktop.org/"
SRC_URI=""

# This package uses the MIT license inherited from Xorg but fails to provide
# any license file in its source, so we add X as a license, which lists all
# the Xorg copyright holders and allows license generation to pick them up.
LICENSE="|| ( MIT X )"
SLOT="0"
if [[ ${PV} = *9999* ]]; then
	KEYWORDS="~*"
else
	KEYWORDS="*"
fi
VIDEO_CARDS="amdgpu exynos freedreno nouveau omap radeon vc4 vmware"
for card in ${VIDEO_CARDS}; do
	IUSE_VIDEO_CARDS+=" video_cards_${card}"
done

IUSE="${IUSE_VIDEO_CARDS} libkms manpages +udev"
RESTRICT="test" # see bug #236845

RDEPEND=""
DEPEND="${RDEPEND}"

PATCHES=(
	"${FILESDIR}/Add-header-for-Rockchip-DRM-userspace.patch"
	"${FILESDIR}/Add-header-for-Mediatek-DRM-userspace.patch"
	"${FILESDIR}/Add-Evdi-module-userspace-api-file.patch"
	"${FILESDIR}/Add-Rockchip-AFBC-modifier.patch"
	"${FILESDIR}/Add-back-VENDOR_NV-name.patch"
	"${FILESDIR}/CHROMIUM-add-resource-info-header.patch"
)

src_configure() {
	# FIXME(tfiga): Could inherit arc-build invoke this implicitly?
	arc-build-select-clang
	multilib-minimal_src_configure
}

multilib_src_configure() {
	arc-build-create-cross-file

	local emesonargs=(
		-Dinstall-test-programs=false
		$(meson_use video_cards_amdgpu amdgpu)
		$(meson_use video_cards_exynos exynos)
		$(meson_use video_cards_freedreno freedreno)
		$(meson_use video_cards_nouveau nouveau)
		$(meson_use video_cards_omap omap)
		$(meson_use video_cards_radeon radeon)
		$(meson_use video_cards_vc4 vc4)
		$(meson_use video_cards_vmware vmwgfx)
		$(meson_use libkms)
		$(meson_use manpages man-pages)
		$(meson_use udev)
		-Dcairo-tests=false
		-Dintel=false
		--prefix="${ARC_PREFIX}/vendor"
		--datadir="${ARC_PREFIX}/vendor/usr/share"
		--cross-file="${ARC_CROSS_FILE}"
	)
	meson_src_configure
}

multilib_src_compile() {
	meson_src_compile
}

multilib_src_install() {
	meson_src_install
}
