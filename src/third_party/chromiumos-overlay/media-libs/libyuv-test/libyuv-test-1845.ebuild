# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

inherit cmake-utils flag-o-matic

DESCRIPTION="YUV library"
LIBRARY_NAME="libyuv"
HOMEPAGE="https://chromium.googlesource.com/libyuv/libyuv"
GIT_SHA1="b9adaef1133ee835efc8970d1dcdcf23a5b68eba"
SRC_URI="${HOMEPAGE}/+archive/${GIT_SHA1}.tar.gz -> ${LIBRARY_NAME}-${PV}.tar.gz"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND="
	dev-cpp/gtest:=
	virtual/jpeg:0"

RDEPEND="${DEPEND}"

S="${WORKDIR}"

src_configure() {
	append-lfs-flags

	local mycmakeargs=(
		-DCMAKE_INSTALL_PREFIX="/usr/lib"
		-DCMAKE_BUILD_TYPE="Release"
		-DTEST=ON
	)

	cmake-utils_src_configure
}

src_install() {
	newbin "${BUILD_DIR}/libyuv_unittest" libyuv_perftest
}
