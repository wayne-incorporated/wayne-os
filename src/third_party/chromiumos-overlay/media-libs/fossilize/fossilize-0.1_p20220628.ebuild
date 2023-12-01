# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit cmake

DESCRIPTION="Serialization format for persistent Vulkan object types."
HOMEPAGE="https://github.com/ValveSoftware/Fossilize"

GIT_REV="6cd06f8139634c0dce9ca1c859aff47c8d918813"

SPIRV_CROSS_GIT_REV="c2500e504d2b823d73d2f129e4f4f050e9618ecb"
SPIRV_HEADERS_GIT_REV="36c0c1596225e728bd49abb7ef56a3953e7ed468"
SPIRV_TOOLS_GIT_REV="37d2396cabe56b29d37551ea55d0d745d5748ded"
DIRENT_GIT_REV="c885633e126a3a949ec0497273ec13e2c03e862c"
VOLK_GIT_REV="760a782f295a66de7391d6ed573d65e3fb1c8450"
RAPIDJSON_GIT_REV="8f4c021fa2f1e001d2376095928fc0532adf2ae6"

SRC_URI="
https://github.com/ValveSoftware/Fossilize/archive/${GIT_REV}.tar.gz -> fossilize-${GIT_REV}.tar.gz
https://github.com/KhronosGroup/SPIRV-Cross/archive/${SPIRV_CROSS_GIT_REV}.tar.gz -> SPIRV-Cross-${SPIRV_CROSS_GIT_REV}.tar.gz
https://github.com/KhronosGroup/SPIRV-Headers/archive/${SPIRV_HEADERS_GIT_REV}.tar.gz -> SPIRV-Headers-${SPIRV_HEADERS_GIT_REV}.tar.gz
https://github.com/KhronosGroup/SPIRV-Tools/archive/${SPIRV_TOOLS_GIT_REV}.tar.gz -> SPIRV-Tools-${SPIRV_TOOLS_GIT_REV}.tar.gz
https://github.com/tronkko/dirent/archive/${DIRENT_GIT_REV}.tar.gz -> dirent-${DIRENT_GIT_REV}.tar.gz
https://github.com/zeux/volk/archive/${VOLK_GIT_REV}.tar.gz -> volk-${VOLK_GIT_REV}.tar.gz
https://github.com/miloyip/rapidjson/archive/${RAPIDJSON_GIT_REV}.tar.gz -> rapidjson-${RAPIDJSON_GIT_REV}.tar.gz
"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	media-libs/vulkan-loader
	virtual/vulkan-icd
"
DEPEND="
	dev-util/vulkan-headers
"

FOSSILIZE_ROOT_DIR="${WORKDIR}/Fossilize-${GIT_REV}"
S="${FOSSILIZE_ROOT_DIR}"

src_unpack() {
	default

	pushd "${FOSSILIZE_ROOT_DIR}" || die
	mv -T "../SPIRV-Cross-${SPIRV_CROSS_GIT_REV}" cli/SPIRV-Cross || die
	mv -T "../SPIRV-Headers-${SPIRV_HEADERS_GIT_REV}" cli/SPIRV-Headers \
		|| die
	mv -T "../SPIRV-Tools-${SPIRV_TOOLS_GIT_REV}" cli/SPIRV-Tools || die
	mv -T "../dirent-${DIRENT_GIT_REV}" cli/dirent || die
	mv -T "../volk-${VOLK_GIT_REV}" cli/volk || die
	mv -T "../rapidjson-${RAPIDJSON_GIT_REV}" rapidjson || die
	popd || die
}

src_configure() {
	append-flags -Wno-unqualified-std-cast-call
	cros_enable_cxx_exceptions
	cmake_src_configure
}

src_install() {
	dobin "${BUILD_DIR}/cli/fossilize-replay"
}
