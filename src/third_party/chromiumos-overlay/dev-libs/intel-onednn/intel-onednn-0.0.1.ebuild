# Copyright 1999-2018 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cmake-utils git-r3 flag-o-matic

DESCRIPTION="Intel oneAPI Deep Neural Network Library (oneDNN)"
HOMEPAGE="https://github.com/oneapi-src/oneDNN"

CMAKE_BUILD_TYPE="Debug"
LICENSE="Apache-2.0 MIT BSD-2 BSD-3 Boost-1.0"
KEYWORDS="-* amd64"
IUSE="+clang"
SLOT="0"

DEPEND="
    dev-util/opencl-headers
"

src_unpack() {
	EGIT_REPO_URI="https://github.com/oneapi-src/oneDNN.git" \
	EGIT_CHECKOUT_DIR="${S}" \
	EGIT_COMMIT="efbf9b5e8c12666314f3484ce279cee0a1a91a44" \
	EGIT_BRANCH="rls-v2.6" \
	git-r3_src_unpack
}

src_configure() {
    cros_enable_cxx_exceptions

    local mycmakeargs=(
        -DDNNL_GPU_RUNTIME=OCL
        -DDNNL_CPU_RUNTIME=NONE
        -DDNNL_BUILD_TESTS=OFF
    )
    cmake-utils_src_configure
}
