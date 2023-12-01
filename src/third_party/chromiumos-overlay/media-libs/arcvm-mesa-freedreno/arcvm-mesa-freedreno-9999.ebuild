# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_PROJECT="chromiumos/third_party/mesa"
CROS_WORKON_LOCALNAME="mesa-freedreno"
CROS_WORKON_EGIT_BRANCH="chromeos-freedreno"

inherit meson multilib-minimal flag-o-matic toolchain-funcs cros-workon arc-build

DESCRIPTION="OpenGL-like graphic library for Linux"
HOMEPAGE="http://mesa3d.sourceforge.net/"

# Most of the code is MIT/X11.
# ralloc is LGPL-3
# GLES[2]/gl[2]{,ext,platform}.h are SGI-B-2.0
LICENSE="MIT LGPL-3 SGI-B-2.0"
SLOT="0"
KEYWORDS="~*"

IUSE="
	cheets
	cheets_user
	cheets_user_64
	debug
	selinux
"

REQUIRED_USE="
	cheets
"

DEPEND="cheets? (
		>=x11-libs/arc-libdrm-2.4.82[${MULTILIB_USEDEP}]
	)"

RDEPEND="${DEPEND}"

# Fix lint errors
: "${ARC_VM_PREFIX:=}"
: "${ARC_SYSROOT:=}"

pkg_setup() {
	# workaround for b/226576333. Also, lld is faster then gold
	append-flags -fuse-ld=lld
}

src_prepare() {
	# workaround for cros-workon not preserving git metadata
	if [[ ${PV} == 9999* && "${CROS_WORKON_INPLACE}" != "1" ]]; then
		echo "#define MESA_GIT_SHA1 \"git-deadbeef\"" > src/git_sha1.h
	fi

	default
}

src_configure() {
	cros_optimize_package_for_speed
	arc-build-select-clang
	multilib-minimal_src_configure
}

multilib_src_configure() {
	tc-getPROG PKG_CONFIG pkg-config

	# The AOSP build system defines the Make variable
	# PLATFORM_SDK_VERSION, and Mesa's Android.mk files use it to
	# define the macro ANDROID_API_LEVEL. Arc emulates that here.
	if [[ -n "${ARC_PLATFORM_SDK_VERSION}" ]]; then
		CPPFLAGS+=" -DANDROID_API_LEVEL=${ARC_PLATFORM_SDK_VERSION}"
	fi

	arc-build-create-cross-file

	emesonargs+=(
		--prefix="${ARC_VM_PREFIX}/vendor"
		--sysconfdir=/system/vendor/etc
		-Ddri-search-path="/system/$(get_libdir)/dri:/system/vendor/$(get_libdir)/dri"
		-Dgallium-va=disabled
		-Dgallium-vdpau=disabled
		-Dgallium-omx=disabled
		-Dglx=disabled
		-Ddri3=disabled
		-Dgles-lib-suffix=_mesa
		-Degl-lib-suffix=_mesa
		-Dfreedreno-kmds=msm,virtio
		-Dplatforms="android"
		-Dllvm=disabled
		-Degl=enabled
		-Dgbm=disabled
		-Dgles1=enabled
		-Dgles2=enabled
		-Dshared-glapi=enabled
		$(meson_use selinux)
		-Dgallium-drivers="virgl,freedreno"
		-Dvulkan-drivers=
		--buildtype $(usex debug debug release)
		--cross-file="${ARC_CROSS_FILE}"
		-Dplatform-sdk-version="${ARC_PLATFORM_SDK_VERSION}"
	)

	meson_src_configure
}

# The meson eclass exports src_compile but not multilib_src_compile. src_compile
# gets overridden by multilib-minimal
multilib_src_compile() {
	meson_src_compile
}

multilib_src_install() {
	exeinto "${ARC_VM_PREFIX}/vendor/$(get_libdir)"
	newexe "${BUILD_DIR}/src/mapi/shared-glapi/libglapi.so.0" libglapi.so.0

	exeinto "${ARC_VM_PREFIX}/vendor/$(get_libdir)/egl"
	newexe "${BUILD_DIR}/src/egl/libEGL_mesa.so" libEGL_mesa.so
	newexe "${BUILD_DIR}/src/mapi/es1api/libGLESv1_CM_mesa.so" libGLESv1_CM_mesa.so
	newexe "${BUILD_DIR}/src/mapi/es2api/libGLESv2_mesa.so" libGLESv2_mesa.so

	exeinto "${ARC_VM_PREFIX}/vendor/$(get_libdir)/dri"
	newexe "${BUILD_DIR}/src/gallium/targets/dri/libgallium_dri.so" virtio_gpu_dri.so
}

multilib_src_install_all() {
	# For documentation on the feature set represented by each XML file
	# installed into /vendor/etc/permissions, see
	# <https://developer.android.com/reference/android/content/pm/PackageManager.html>.
	# For example XML files for each feature, see
	# <https://android.googlesource.com/platform/frameworks/native/+/master/data/etc>.

	# Install init files to advertise supported API versions.
	insinto "${ARC_VM_PREFIX}/vendor/etc/init"
	doins "${FILESDIR}/gles32.rc"

	# Install permission file to declare opengles aep support.
	insinto "${ARC_VM_PREFIX}/vendor/etc/permissions"
	doins "${FILESDIR}/android.hardware.opengles.aep.xml"

	# Install the dri header for arc-cros-gralloc
	insinto "${ARC_VM_PREFIX}/vendor/include/GL"
	doins -r "${S}/include/GL/internal"
}
