# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_PROJECT="chromiumos/third_party/mesa"
CROS_WORKON_LOCALNAME="mesa-amd"
CROS_WORKON_EGIT_BRANCH="chromeos-amd"

inherit meson multilib-minimal flag-o-matic cros-workon arc-build

DESCRIPTION="The Mesa 3D Graphics Library"
HOMEPAGE="http://mesa3d.org/"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~*"

IUSE="
	debug
	vulkan
	-android_vulkan_compute_0
"

REQUIRED_USE="
	android_vulkan_compute_0? ( vulkan )
"

DEPEND="
	>=x11-libs/arc-libdrm-2.4.82[${MULTILIB_USEDEP}]
	sys-devel/arc-llvm:=[${MULTILIB_USEDEP}]
	dev-libs/arc-libelf[${MULTILIB_USEDEP}]
"

RDEPEND="${DEPEND} !media-libs/arc-mesa"

BDEPEND="
	sys-devel/bison
	sys-devel/flex
	virtual/pkgconfig
"

src_configure() {
	cros_optimize_package_for_speed

	arc-build-select-clang

	multilib-minimal_src_configure
}

multilib_src_configure() {
	# Use llvm-config coming from ARC++ build.
	export LLVM_CONFIG="${ARC_SYSROOT:?}/build/bin/llvm-config-host"

	arc-build-create-cross-file

	emesonargs+=(
		--prefix="${ARC_PREFIX}/vendor"
		--sysconfdir="/system/vendor/etc"
		-Ddri-search-path="/system/$(get_libdir)/dri:/system/vendor/$(get_libdir)/dri"
		-Dgallium-va=disabled
		-Dgallium-vdpau=disabled
		-Dgallium-omx=disabled
		-Dgallium-xa=disabled
		-Dglx=disabled
		-Ddri3=disabled
		-Dgles-lib-suffix=_mesa
		-Degl-lib-suffix=_mesa
		-Dllvm=enabled
		-Dshared-llvm=disabled
		-Dplatforms=android
		-Degl=enabled
		-Dgbm=disabled
		-Dgles1=enabled
		-Dgles2=enabled
		-Dshared-glapi=enabled
		-Dgallium-drivers=radeonsi
		-Dvulkan-drivers=$(usex vulkan amd '')
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
	newexe "${BUILD_DIR}/src/gallium/targets/dri/libgallium_dri.so" radeonsi_dri.so

	if use vulkan; then
		exeinto "${ARC_PREFIX}/vendor/$(get_libdir)/hw"
		newexe "${BUILD_DIR}/src/amd/vulkan/libvulkan_radeon.so" vulkan.cheets.so
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
	doins "${FILESDIR}/init.gpu.rc"

	# Install vulkan related files.
	if use vulkan; then
		einfo "Using android vulkan."
		insinto "${ARC_PREFIX}/vendor/etc/init"
		doins "${FILESDIR}/vulkan.rc"

		insinto "${ARC_PREFIX}/vendor/etc/permissions"
		doins "${FILESDIR}/android.hardware.vulkan.level-0.xml"

		# advertise 1.1 on R and later (api level 30+), where ndk_translation
		# is new enough
		if [[ "${ARC_PLATFORM_SDK_VERSION}" -ge 30 ]]; then
			doins "${FILESDIR}/android.hardware.vulkan.version-1_1.xml"
		else
			doins "${FILESDIR}/android.hardware.vulkan.version-1_0_3.xml"
		fi
	fi

	if use android_vulkan_compute_0; then
		einfo "Using android vulkan_compute_0."
		insinto "${ARC_PREFIX}/vendor/etc/permissions"
		doins "${FILESDIR}/android.hardware.vulkan.compute-0.xml"
	fi

	# Install permission file to declare opengles aep support.
	einfo "Using android aep."
	insinto "${ARC_PREFIX}/vendor/etc/permissions"
	doins "${FILESDIR}/android.hardware.opengles.aep.xml"

	# Install the dri header for arc-cros-gralloc
	insinto "${ARC_PREFIX}/vendor/include/GL"
	doins -r "${S}/include/GL/internal"
}
