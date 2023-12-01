# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT="chromiumos/third_party/mesa"
CROS_WORKON_LOCALNAME="mesa-iris"
CROS_WORKON_EGIT_BRANCH="chromeos-iris"

KEYWORDS="~*"

inherit meson flag-o-matic cros-workon cros-sanitizers

DESCRIPTION="The Mesa 3D Graphics Library"
HOMEPAGE="http://mesa3d.org/"

# Most of the code is MIT/X11.
# GLES[2]/gl[2]{,ext,platform}.h are SGI-B-2.0
LICENSE="MIT SGI-B-2.0"

IUSE="borealis_host debug libglvnd perfetto tools vulkan zstd"

COMMON_DEPEND="
	dev-libs/expat:=
	>=x11-libs/libdrm-2.4.94:=
"

RDEPEND="${COMMON_DEPEND}
	libglvnd? ( media-libs/libglvnd )
	!libglvnd? ( !media-libs/libglvnd )
	zstd? ( app-arch/zstd )
"

DEPEND="${COMMON_DEPEND}
	perfetto? ( >=chromeos-base/perfetto-29.0 )
"

BDEPEND="
	sys-devel/bison
	sys-devel/flex
	virtual/pkgconfig
"

src_configure() {
	sanitizers-setup-env
	cros_optimize_package_for_speed

	if use borealis_host; then
		tools=intel,drm-shim
	elif use tools; then
		tools=intel
	else
		tools=''
	fi

	emesonargs+=(
		-Dexecmem=false
		-Dglvnd=$(usex libglvnd true false)
		-Dllvm=disabled
		-Ddri3=disabled
		-Dshader-cache-default=false
		-Dglx=disabled
		-Degl=enabled
		-Dgbm=disabled
		-Dgles1=disabled
		-Dgles2=enabled
		-Dshared-glapi=enabled
		-Dgallium-drivers=iris
		-Dgallium-vdpau=disabled
		-Dgallium-xa=disabled
		-Dglvnd=$(usex libglvnd true false)
		-Dperfetto=$(usex perfetto true false)
		$(meson_feature zstd)
		# Set platforms empty to avoid the default "auto" setting. If
		# platforms is empty meson.build will add surfaceless.
		-Dplatforms=''
		-Dtools="${tools}"
		--buildtype $(usex debug debug release)
		-Dvulkan-drivers=$(usex vulkan intel '')
	)

	meson_src_configure
}

src_install() {
	meson_src_install

	rm -v -rf "${ED}/usr/include"
}
