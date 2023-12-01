# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the MIT License

EAPI=7

inherit cmake-utils flag-o-matic git-r3

DESCRIPTION="Intel(R) Versatile Processing Unit User-mode driver"
HOMEPAGE="https://github.com/intel/linux-vpu-driver"
SRC_URI="gs://chromeos-localmirror/distfiles/$P-files.tar.xz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="-* amd64"
IUSE="+clang vpu_driver"

DEPEND="
	dev-libs/boost
"

RDEPEND="${DEPEND}"

CMAKE_BUILD_TYPE="Release"

src_unpack() {
	EGIT_REPO_URI="https://github.com/intel/linux-vpu-driver.git" \
	EGIT_CHECKOUT_DIR="${S}" \
	EGIT_COMMIT="aa2163dc785580b0363710b789768d0a64bb8bb6" \
	EGIT_BRANCH="main" \
	git-r3_src_unpack
}

src_prepare() {
	cros_enable_cxx_exceptions
	eapply_user
	unpack ${DISTDIR}/$P-files.tar.xz
	cmake-utils_src_prepare
}

src_configure() {
	cros_enable_cxx_exceptions

	local mycmakeargs=(
		-DSKIP_UNIT_TESTS=ON
		-DENABLE_VPUX_COMPILER=OFF
	)
	cmake-utils_src_configure
}

src_install() {
	cmake-utils_src_install

	if use vpu_driver ; then
		dolib.so ${BUILD_DIR}/lib/libze_intel_vpu.so.1.1.0
		dosym libze_intel_vpu.so.1.1.0 /usr/$(get_libdir)/libze_intel_vpu.so.1
		dosym libze_intel_vpu.so.1 /usr/$(get_libdir)/libze_intel_vpu.so

		dolib.so ${BUILD_DIR}/lib/libze_loader.so.1.8.5
		dosym libze_loader.so.1.8.5 /usr/$(get_libdir)/libze_loader.so.1
		dosym libze_loader.so.1 /usr/$(get_libdir)/libze_loader.so

		insinto /lib/firmware
		doins "${S}"/fw/mtl_vpu_v0.0.bin
		dosym mtl_vpu_v0.0.bin /lib/firmware/mtl_vpu.bin
	fi
}
