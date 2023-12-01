# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT="chromiumos/third_party/mesa"
CROS_WORKON_EGIT_BRANCH="chromeos-reven"
CROS_WORKON_LOCALNAME="mesa-reven"

inherit flag-o-matic meson toolchain-funcs cros-workon

DESCRIPTION="The Mesa 3D Graphics Library"
HOMEPAGE="http://mesa3d.org/"

# Most of the code is MIT/X11.
# ralloc is LGPL-3
# GLES[2]/gl[2]{,ext,platform}.h are SGI-B-2.0
LICENSE="MIT LGPL-3 SGI-B-2.0"
KEYWORDS="~*"

VIDEO_CARDS="amdgpu intel iris llvmpipe nouveau radeon virgl vmware"
for card in ${VIDEO_CARDS}; do
	IUSE_VIDEO_CARDS+=" video_cards_${card}"
done

IUSE="${IUSE_VIDEO_CARDS}
	debug dri egl +gallium -gbm gles1 gles2
	kvm_guest llvm +nptl pic selinux shared-glapi vulkan wayland zstd
	libglvnd"

REQUIRED_USE="video_cards_amdgpu? ( llvm )
	video_cards_llvmpipe? ( llvm )"

COMMON_DEPEND="
	dev-libs/expat:=
	llvm? ( virtual/libelf:= )
	x11-libs/libva:=
	zstd? ( app-arch/zstd )
	>=x11-libs/libdrm-2.4.60:=
"

RDEPEND="${COMMON_DEPEND}
	libglvnd? ( media-libs/libglvnd:= )
"

DEPEND="${COMMON_DEPEND}
	dev-libs/libxml2:=
	x11-base/xorg-proto:=
	llvm? ( sys-devel/llvm:= )
	wayland? ( >=dev-libs/wayland-protocols-1.8:= )
"

BDEPEND="
	virtual/pkgconfig
	sys-devel/bison
	sys-devel/flex
"

driver_list() {
	local drivers="$(sort -u <<< "${1// /$'\n'}")"
	echo "${drivers//$'\n'/,}"
}

src_configure() {
	tc-getPROG PKG_CONFIG pkg-config

	cros_optimize_package_for_speed
	# For llvmpipe on ARM we'll get errors about being unable to resolve
	# "__aeabi_unwind_cpp_pr1" if we don't include this flag; seems wise
	# to include it for all platforms though.
	use video_cards_llvmpipe && append-flags "-rtlib=libgcc -shared-libgcc --unwindlib=libgcc -lpthread"

	if use !gallium && use !vulkan; then
		ewarn "You enabled neither gallium nor vulkan "
		ewarn "USE flags. No hardware drivers will be built."
	fi

	# Configurable gallium drivers
	if use gallium; then
		gallium_enable video_cards_llvmpipe swrast

		# Intel code
		gallium_enable video_cards_intel crocus
		gallium_enable video_cards_iris iris

		# Nouveau code
		gallium_enable video_cards_nouveau nouveau

		# ATI code
		gallium_enable video_cards_radeon r300 r600
		gallium_enable video_cards_amdgpu radeonsi

		gallium_enable video_cards_virgl virgl

		gallium_enable video_cards_vmware svga
	fi

	if use vulkan; then
		vulkan_enable video_cards_intel intel
		vulkan_enable video_cards_amdgpu amd
	fi

	LLVM_ENABLE=false
	if use llvm; then
		emesonargs+=( -Dshared-llvm=disabled )
		export LLVM_CONFIG=${SYSROOT}/usr/lib/llvm/bin/llvm-config-host
		LLVM_ENABLE=true
	fi

	if use kvm_guest; then
		emesonargs+=( -Ddri-search-path=/opt/google/cros-containers/lib )
	fi

	emesonargs+=(
		-Dexecmem=false
		-Dglx=disabled
		-Dllvm="${LLVM_ENABLE}"
		# Set platforms empty to get only surfaceless. This works better
		# than explicitly setting surfaceless because it forces it to be
		# the default. b/206629705
		-Dplatforms=''
		-Dshader-cache-default=false
		$(meson_use libglvnd glvnd)
		$(meson_feature egl)
		$(meson_feature gbm)
		$(meson_feature gles1)
		$(meson_feature gles2)
		$(meson_feature zstd)
		$(meson_use selinux)
		-Dgallium-drivers="$(driver_list "${GALLIUM_DRIVERS[*]}")"
		-Dvulkan-drivers="$(driver_list "${VULKAN_DRIVERS[*]}")"
		--buildtype $(usex debug debug release)
		-Dgallium-va=enabled
		-Dva-libs-path="${EPREFIX}/usr/$(get_libdir)/va/drivers"
		-Dvideo-codecs="h264dec,h264enc,h265dec,h265enc,vc1dec"
	)

	meson_src_configure
}

src_install() {
	meson_src_install

	# Remove redundant GLES headers
	rm -f "${D}"/usr/include/{EGL,GLES2,GLES3,KHR}/*.h || die "Removing GLES headers failed."

	# Set driconf option to enable S3TC hardware decompression
	insinto "/etc/"
	doins "${FILESDIR}"/drirc
}

# $1 - VIDEO_CARDS flag (check skipped for "--")
# other args - names of drivers to enable

gallium_enable() {
	if [[ $1 == -- ]] || use "$1"; then
		shift
		GALLIUM_DRIVERS+=("$@")
	fi
}

vulkan_enable() {
	if [[ $1 == -- ]] || use "$1"; then
		shift
		VULKAN_DRIVERS+=("$@")
	fi
}
