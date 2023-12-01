# Copyright 1999-2019 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/media-libs/mesa/mesa-7.9.ebuild,v 1.3 2010/12/05 17:19:14 arfrever Exp $

EAPI=7

CROS_WORKON_COMMIT="813ee839be2ce7c3c804dc90cba5678323bcad7c"
CROS_WORKON_TREE="b09304eab38348e2a157c4adc75542a460746ce9"

EGIT_REPO_URI="git://anongit.freedesktop.org/mesa/mesa"
CROS_WORKON_PROJECT="chromiumos/third_party/mesa"
CROS_WORKON_EGIT_BRANCH="mesa-img"
CROS_WORKON_MANUAL_UPREV="1"

if [[ ${PV} = 9999* ]]; then
	GIT_ECLASS="git-2"
	EXPERIMENTAL="true"
fi

inherit multilib flag-o-matic meson toolchain-funcs ${GIT_ECLASS} cros-workon

FOLDER="${PV/_rc*/}"
[[ ${PV/_rc*/} == ${PV} ]] || FOLDER+="/RC"

DESCRIPTION="OpenGL-like graphic library for Linux"
HOMEPAGE="http://mesa3d.sourceforge.net/"

# Most of the code is MIT/X11.
# ralloc is LGPL-3
# GLES[2]/gl[2]{,ext,platform}.h are SGI-B-2.0
LICENSE="MIT LGPL-3 SGI-B-2.0"
SLOT="0"
KEYWORDS="*"

INTEL_CARDS="intel"
RADEON_CARDS="amdgpu radeon"
VIDEO_CARDS="${INTEL_CARDS} ${RADEON_CARDS} freedreno llvmpipe mach64 mga nouveau powervr r128 radeonsi savage sis softpipe tdfx via virgl vmware"
for card in ${VIDEO_CARDS}; do
	IUSE_VIDEO_CARDS+=" video_cards_${card}"
done

IUSE="${IUSE_VIDEO_CARDS}
	+classic debug dri drm egl -gallium -gbm gles1 gles2 kernel_FreeBSD
	kvm_guest -llvm +nptl pic selinux shared-glapi vulkan wayland xlib-glx X
	libglvnd zstd"

LIBDRM_DEPSTRING=">=x11-libs/libdrm-2.4.60"

REQUIRED_USE="video_cards_amdgpu? ( llvm )
	video_cards_llvmpipe? ( llvm )"

# keep correct libdrm and dri2proto dep
# keep blocks in rdepend for binpkg
RDEPEND="
	libglvnd? ( media-libs/libglvnd )
	!libglvnd? ( !media-libs/libglvnd )
	!media-libs/mesa
	X? (
		!<x11-base/xorg-server-1.7
		>=x11-libs/libX11-1.3.99.901
		x11-libs/libXdamage
		x11-libs/libXext
		x11-libs/libXrandr
		x11-libs/libXxf86vm
	)
	llvm? ( virtual/libelf )
	dev-libs/expat
	${LIBDRM_DEPSTRING}
"

DEPEND="${RDEPEND}
	dev-libs/libxml2
	sys-devel/bison
	sys-devel/flex
	virtual/pkgconfig
	x11-base/xorg-proto
	wayland? ( >=dev-libs/wayland-protocols-1.8 )
	llvm? ( sys-devel/llvm )
	video_cards_powervr? (
		virtual/img-ddk
		!<media-libs/img-ddk-1.13
		!<media-libs/img-ddk-bin-1.13
	)
"

PATCHES=(
	"${FILESDIR}"/FROMLIST-anv-advertise-rectangularLines-only-for-Gen10.patch
	"${FILESDIR}"/0001-Add-pvr-dri-driver.patch
	"${FILESDIR}"/0002-Force-Mesa-to-use-the-PVR-driver-for-platform-device.patch
	"${FILESDIR}"/0003-dri-Add-some-new-DRI-formats-and-fourccs.patch
	"${FILESDIR}"/0004-GL_EXT_sparse_texture-entry-points.patch
	"${FILESDIR}"/0005-Add-support-for-various-GLES-extensions.patch
	"${FILESDIR}"/0009-GL_EXT_shader_pixel_local_storage2-entry-points.patch
	"${FILESDIR}"/0010-GL_IMG_framebuffer_downsample-entry-points.patch
	"${FILESDIR}"/0011-GL_OVR_multiview-entry-points.patch
	"${FILESDIR}"/0012-Add-OVR_multiview_multisampled_render_to_texture.patch
	"${FILESDIR}"/0017-egl-automatically-call-eglReleaseThread-on-thread-te.patch
	"${FILESDIR}"/0066-mesa-partially-revert-pbuffer-attribute-removal.patch
	"${FILESDIR}"/0067-egl_dri2-set-pbuffer-config-attribs-to-0-for-non-pbu.patch
)

driver_list() {
	local drivers="$(sort -u <<< "${1// /$'\n'}")"
	echo "${drivers//$'\n'/,}"
}

src_prepare() {
	# FreeBSD 6.* doesn't have posix_memalign().
	if [[ ${CHOST} == *-freebsd6.* ]]; then
		sed -i \
			-e "s/-DHAVE_POSIX_MEMALIGN//" \
			configure.ac || die
	fi

	# Produce a dummy git_sha1.h file because .git will not be copied to portage tmp directory
	echo '#define MESA_GIT_SHA1 "git-0000000"' > src/git_sha1.h
	default
}

src_configure() {
	tc-getPROG PKG_CONFIG pkg-config

	cros_optimize_package_for_speed

	#
	# No gallium, IMG code
	#

	dri_driver_enable video_cards_powervr pvr

	#
	# No Vulkan, IMG vulkan driver is part of img-ddk nothing to do here
	#

	LLVM_ENABLE=false
	if use llvm && use !video_cards_softpipe; then
		emesonargs+=( -Dshared-llvm=false )
		export LLVM_CONFIG=${SYSROOT}/usr/lib/llvm/bin/llvm-config-host
		LLVM_ENABLE=true
	fi

	local egl_platforms=""
	if use egl; then
		if use wayland; then
			egl_platforms="${egl_platforms},wayland"
		fi

		if use X; then
			egl_platforms="${egl_platforms},x11"
		fi
	fi
	egl_platforms="${egl_platforms##,}"

	if use X; then
		glx="dri"
	else
		glx="disabled"
	fi

	if use kvm_guest; then
		emesonargs+=( -Ddri-search-path=/opt/google/cros-containers/lib )
	fi

	emesonargs+=(
		-Dexecmem=false
		-Dglvnd=$(usex libglvnd true false)
		-Dglx="${glx}"
		-Dllvm="${LLVM_ENABLE}"
		-Dplatforms="${egl_platforms}"
		-Dprefer-iris=false
		-Dshader-cache-default=false
		$(meson_use egl)
		$(meson_use gbm)
		$(meson_use gles1)
		$(meson_use gles2)
		$(meson_feature zstd)
		$(meson_use selinux)
		-Ddri-drivers=$(driver_list "${DRI_DRIVERS[*]}")
		-Dgallium-drivers=$(driver_list "${GALLIUM_DRIVERS[*]}")
		-Dvulkan-drivers=$(driver_list "${VULKAN_DRIVERS[*]}")
		--buildtype $(usex debug debug release)
	)

	meson_src_configure
}

src_install() {
	meson_src_install

	# Remove redundant GLES headers
	rm -f "${D}"/usr/include/{EGL,GLES2,GLES3,KHR}/*.h || die "Removing GLES headers failed."

	dodir /usr/$(get_libdir)/dri
	insinto "/usr/$(get_libdir)/dri/"
	insopts -m0755
	# install the gallium drivers we use
	local gallium_drivers_files=( nouveau_dri.so r300_dri.so r600_dri.so msm_dri.so swrast_dri.so )
	for x in ${gallium_drivers_files[@]}; do
		if [ -f "${S}/$(get_libdir)/gallium/${x}" ]; then
			doins "${S}/$(get_libdir)/gallium/${x}"
		fi
	done

	# install classic drivers we use
	local classic_drivers_files=( i810_dri.so i965_dri.so nouveau_vieux_dri.so radeon_dri.so r200_dri.so )
	for x in ${classic_drivers_files[@]}; do
		if [ -f "${S}/$(get_libdir)/${x}" ]; then
			doins "${S}/$(get_libdir)/${x}"
		fi
	done

	# Set driconf option to enable S3TC hardware decompression
	insinto "/etc/"
	doins "${FILESDIR}"/drirc
}

# $1 - VIDEO_CARDS flag (check skipped for "--")
# other args - names of DRI drivers to enable
dri_driver_enable() {
	if [[ $1 == -- ]] || use $1; then
		shift
		DRI_DRIVERS+=("$@")
	fi
}

gallium_enable() {
	if [[ $1 == -- ]] || use $1; then
		shift
		GALLIUM_DRIVERS+=("$@")
	fi
}

vulkan_enable() {
	if [[ $1 == -- ]] || use $1; then
		shift
		VULKAN_DRIVERS+=("$@")
	fi
}
