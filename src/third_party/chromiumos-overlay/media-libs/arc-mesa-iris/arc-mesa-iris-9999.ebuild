# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_PROJECT="chromiumos/third_party/mesa"
CROS_WORKON_LOCALNAME="mesa-iris"
CROS_WORKON_EGIT_BRANCH="chromeos-iris"

inherit meson multilib-minimal flag-o-matic cros-workon arc-build

DESCRIPTION="The Mesa 3D Graphics Library"
HOMEPAGE="http://mesa3d.org/"

KEYWORDS="~*"

# Most files are MIT/X11.
# Some files in src/glx are SGI-B-2.0.
LICENSE="MIT SGI-B-2.0"
SLOT="0"

IUSE="
	cheets
	cheets_user
	cheets_user_64
	debug
	vulkan
	android_vulkan_compute_0
	android_aep
"

REQUIRED_USE="
	cheets
	android_vulkan_compute_0? ( vulkan )
"

DEPEND="
	>=x11-libs/arc-libdrm-2.4.82[${MULTILIB_USEDEP}]
	dev-libs/arc-libelf[${MULTILIB_USEDEP}]
"

RDEPEND="${DEPEND}"

src_configure() {
	cros_optimize_package_for_speed

	arc-build-select-clang

	multilib-minimal_src_configure
}

multilib_src_configure() {
	# The AOSP build system defines the Make variable PLATFORM_SDK_VERSION,
	# and Mesa's Android.mk files use it to define the macro
	# ANDROID_API_LEVEL. Arc emulates that here.
	if [[ -n "${ARC_PLATFORM_SDK_VERSION}" ]]; then
		CPPFLAGS+=" -DANDROID_API_LEVEL=${ARC_PLATFORM_SDK_VERSION}"
	fi

	arc-build-create-cross-file

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
		-Dgallium-drivers=iris
		-Dgallium-vdpau=disabled
		-Dgallium-xa=disabled
		-Dplatforms=android
		-Degl-lib-suffix=_mesa
		-Dgles-lib-suffix=_mesa
		-Dvulkan-drivers=$(usex vulkan intel '')
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
	exeinto "${ARC_PREFIX}/vendor/$(get_libdir)"
	newexe "${BUILD_DIR}/src/mapi/shared-glapi/libglapi.so.0" libglapi.so.0

	exeinto "${ARC_PREFIX}/vendor/$(get_libdir)/egl"
	newexe "${BUILD_DIR}/src/egl/libEGL_mesa.so" libEGL_mesa.so
	newexe "${BUILD_DIR}/src/mapi/es1api/libGLESv1_CM_mesa.so" libGLESv1_CM_mesa.so
	newexe "${BUILD_DIR}/src/mapi/es2api/libGLESv2_mesa.so" libGLESv2_mesa.so

	exeinto "${ARC_PREFIX}/vendor/$(get_libdir)/dri"
	newexe "${BUILD_DIR}/src/gallium/targets/dri/libgallium_dri.so" iris_dri.so

	if use vulkan; then
		exeinto "${ARC_PREFIX}/vendor/$(get_libdir)/hw"
		newexe "${BUILD_DIR}/src/intel/vulkan/libvulkan_intel.so" vulkan.cheets.so
	fi
}

multilib_src_install_all() {
	# For documentation on the feature set represented by each XML file
	# installed into /vendor/etc/permissions, see
	# <https://developer.android.com/reference/android/content/pm/PackageManager.html>.
	# For example XML files for each feature, see
	# <https://android.googlesource.com/platform/frameworks/native/+/master/data/etc>.

	# Install init files to advertise supported API versions.
	insinto "${ARC_PREFIX}/vendor/etc/init"
	doins "${FILESDIR}/gles32.rc"

	# Install vulkan files
	if use vulkan; then
		einfo "Using android vulkan."
		insinto "${ARC_PREFIX}/vendor/etc/init"
		doins "${FILESDIR}/vulkan.rc"

		insinto "${ARC_PREFIX}/vendor/etc/permissions"
		doins "${FILESDIR}/android.hardware.vulkan.level-1.xml"
		doins "${FILESDIR}/android.hardware.vulkan.version-1_1.xml"

		if use android_vulkan_compute_0; then
			einfo "Using android vulkan_compute_0."
			insinto "${ARC_PREFIX}/vendor/etc/permissions"
			doins "${FILESDIR}/android.hardware.vulkan.compute-0.xml"
		fi
	fi

	# Install permission file to declare opengles aep support.
	if use android_aep; then
		einfo "Using android aep."
		insinto "${ARC_PREFIX}/vendor/etc/permissions"
		doins "${FILESDIR}/android.hardware.opengles.aep.xml"
	fi
	# Install the dri header for arc-cros-gralloc
	insinto "${ARC_PREFIX}/vendor/include/GL"
	doins -r "${S}/include/GL/internal"
}
