# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/media-libs/mesa/mesa-7.9.ebuild,v 1.3 2010/12/05 17:19:14 arfrever Exp $

EAPI="7"

CROS_WORKON_COMMIT="33d6d5e44721210e939468567845d366fd70b5f6"
CROS_WORKON_TREE="040a39591a38d3dc778725575c72dcdc1b07e032"
CROS_WORKON_PROJECT="chromiumos/third_party/mesa-img"
CROS_WORKON_LOCALNAME="mesa-img"
CROS_WORKON_EGIT_BRANCH="mesa-img"
CROS_WORKON_MANUAL_UPREV="1"

EGIT_REPO_URI="git://anongit.freedesktop.org/mesa/mesa"

inherit meson multilib-minimal flag-o-matic toolchain-funcs cros-workon arc-build

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
VIDEO_CARDS="${INTEL_CARDS} ${RADEON_CARDS} llvmpipe mach64 mga nouveau powervr r128 savage sis vmware tdfx via freedreno virgl"
for card in ${VIDEO_CARDS}; do
	IUSE_VIDEO_CARDS+=" video_cards_${card}"
done

IUSE="${IUSE_VIDEO_CARDS}
	android_aep -android_gles2 -android_gles30
	+android_gles31 -android_gles32 -android_vulkan_compute_0
	cheets +classic debug dri egl -gallium
	-gbm gles1 gles2 -llvm +nptl pic selinux shared-glapi vulkan X xlib-glx
	cheets_user cheets_user_64"

# llvmpipe requires ARC++ _userdebug images, ARC++ _user images can't use it
# (b/33072485, b/28802929).
# Only allow one vulkan driver as they all write vulkan.cheets.so.
REQUIRED_USE="
	^^ ( android_gles2 android_gles30 android_gles31 android_gles32 )
	android_aep? ( !android_gles2 !android_gles30 )
	android_vulkan_compute_0? ( vulkan )
	cheets? (
		vulkan? ( ^^ ( video_cards_amdgpu video_cards_intel video_cards_powervr ) )
		video_cards_amdgpu? ( llvm )
		video_cards_llvmpipe? ( !cheets_user !cheets_user_64 )
	)"

DEPEND="video_cards_powervr? (
		media-libs/arc-img-ddk
		!<media-libs/arc-img-ddk-1.13
	)
	cheets? (
		>=x11-libs/arc-libdrm-2.4.82[${MULTILIB_USEDEP}]
		llvm? ( sys-devel/arc-llvm:=[${MULTILIB_USEDEP}] )
		video_cards_amdgpu? (
			dev-libs/arc-libelf[${MULTILIB_USEDEP}]
		)
	)"

RDEPEND="${DEPEND}"

src_prepare() {
	# workaround for cros-workon not preserving git metadata
	if [[ ${PV} == 9999* && "${CROS_WORKON_INPLACE}" != "1" ]]; then
		echo "#define MESA_GIT_SHA1 \"git-deadbeef\"" > src/git_sha1.h
	fi

	# Restrict gles version based on USE flag. (See crbug.com/30202361, b/30202371, b/31041422, b:68023287)
	if use android_gles32; then
		einfo "Limiting android to gles32."
		eapply "${FILESDIR}/gles32/0001-limit-gles-version.patch"
	elif use android_gles31; then
		einfo "Limiting android to gles31."
		eapply "${FILESDIR}/gles31/0001-limit-gles-version.patch"
	elif use android_gles30; then
		einfo "Limiting android to gles30."
		eapply "${FILESDIR}/gles30/0001-limit-gles-version.patch"
	elif use android_gles2; then
		einfo "Limiting android to gles2."
		eapply "${FILESDIR}/gles2/0001-limit-gles-version.patch"
	fi

	# One backport needed because we add entry points
	eapply "${FILESDIR}"/BACKPORT-glapi-should-not-add-alias-function-to-static_data.p.patch

	# IMG patches
	eapply "${FILESDIR}"/0001-Add-pvr-dri-driver.patch
	eapply "${FILESDIR}"/0002-Force-Mesa-to-use-the-PVR-driver-for-platform-device.patch
	eapply "${FILESDIR}"/0003-dri-Add-some-new-DRI-formats-and-fourccs.patch
	eapply "${FILESDIR}"/0004-GL_EXT_sparse_texture-entry-points.patch
	eapply "${FILESDIR}"/0005-Add-support-for-various-GLES-extensions.patch
	eapply "${FILESDIR}"/0009-GL_EXT_shader_pixel_local_storage2-entry-points.patch
	eapply "${FILESDIR}"/0010-GL_IMG_framebuffer_downsample-entry-points.patch
	eapply "${FILESDIR}"/0011-GL_OVR_multiview-entry-points.patch
	eapply "${FILESDIR}"/0012-Add-OVR_multiview_multisampled_render_to_texture.patch
	eapply "${FILESDIR}"/0017-egl-automatically-call-eglReleaseThread-on-thread-te.patch
	eapply "${FILESDIR}"/0066-mesa-partially-revert-pbuffer-attribute-removal.patch
	eapply "${FILESDIR}"/0067-egl_dri2-set-pbuffer-config-attribs-to-0-for-non-pbu.patch

	eapply_user
}

src_configure() {
	cros_optimize_package_for_speed

	arc-build-select-clang

	multilib-minimal_src_configure
}

multilib_src_configure() {
	tc-getPROG PKG_CONFIG pkg-config

	arc-build-create-cross-file

	# TODO(drinkcat): We should provide a pkg-config file for this.
	export PVR_CFLAGS="-I${SYSROOT}${ARC_PREFIX}/vendor/include"
	export PVR_LIBS="-L${SYSROOT}${ARC_PREFIX}/vendor/$(get_libdir) -lcutils -llog -lpvr_dri_support "

	emesonargs+=(
		--prefix="${ARC_PREFIX}/vendor"
		--sysconfdir="/system/vendor/etc"
		-Ddri-search-path="/system/$(get_libdir)/dri:/system/vendor/$(get_libdir)/dri"
		-Dllvm=disabled
		-Ddri3=disabled
		-Dshader-cache=enabled
		-Dglx=disabled
		-Degl=enabled
		-Dgbm=disabled
		-Dgles1=enabled
		-Dgles2=enabled
		-Dshared-glapi=enabled
		-Ddri-drivers=pvr
		-Dgallium-drivers=
		-Dgallium-vdpau=disabled
		-Dgallium-xa=disabled
		-Dplatforms=android
		-Dplatform-sdk-version="${ARC_PLATFORM_SDK_VERSION}"
		-Degl-lib-suffix=_mesa
		-Dgles-lib-suffix=_mesa
		--buildtype $(usex debug debug release)
		-Dvulkan-drivers=
		--cross-file="${ARC_CROSS_FILE}"
	)

	meson_src_configure
}

# The meson eclass exports src_compile but not multilib_src_compile. src_compile
# gets overridden by multilib-minimal
multilib_src_compile() {
	meson_src_compile
}

multilib_src_install() {
	exeinto "${ARC_PREFIX}/vendor/$(get_libdir)"
	newexe "${BUILD_DIR}/src/mapi/shared-glapi/libglapi.so.0" libglapi.so.0

	exeinto "${ARC_PREFIX}/vendor/$(get_libdir)/egl"
	newexe "${BUILD_DIR}/src/egl/libEGL_mesa.so" libEGL_mesa.so
	newexe "${BUILD_DIR}/src/mapi/es1api/libGLESv1_CM_mesa.so" libGLESv1_CM_mesa.so
	newexe "${BUILD_DIR}/src/mapi/es2api/libGLESv2_mesa.so" libGLESv2_mesa.so

	exeinto "${ARC_PREFIX}/vendor/$(get_libdir)/dri"
	newexe "${BUILD_DIR}/src/mesa/drivers/dri/libmesa_dri_drivers.so" pvr_dri.so
}

multilib_src_install_all() {
	# Set driconf option to enable S3TC hardware decompression
	insinto "${ARC_PREFIX}/vendor/etc/"
	doins "${FILESDIR}"/drirc

	# For documentation on the feature set represented by each XML file
	# installed into /vendor/etc/permissions, see
	# <https://developer.android.com/reference/android/content/pm/PackageManager.html>.
	# For example XML files for each feature, see
	# <https://android.googlesource.com/platform/frameworks/native/+/master/data/etc>.

	# Install init files to advertise supported API versions.
	#
	# IMG supported API is part of arc-img-ddk
	# nothing to do here
	#

	# Install vulkan related files.
	#
	# IMG vulkan driver is part of arc-img-ddk
	# nothing to do here
	#

	# Do not install android.hardware.opengles.aep.xml to declare opengles aep
	# support, for IMG this comes from arc-img-ddk.

	# Install the dri header for arc-cros-gralloc
	insinto "${ARC_PREFIX}/vendor/include/GL"
	doins -r "${S}/include/GL/internal"
}
