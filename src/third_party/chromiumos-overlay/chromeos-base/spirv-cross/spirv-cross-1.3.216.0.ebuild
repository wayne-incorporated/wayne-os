# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit cmake-utils

DESCRIPTION="SPIR-V Decompiler"
HOMEPAGE="https://github.com/KhronosGroup/SPIRV-Cross"
SRC_URI="https://github.com/KhronosGroup/SPIRV-Cross/archive/refs/tags/sdk-${PV}.tar.gz -> spirv-cross-sdk-${PV}.tar.gz"

LICENSE="Apache-2.0"
KEYWORDS="*"
IUSE=""
SLOT="0"

S="${WORKDIR}/SPIRV-Cross-sdk-${PV}"

src_configure() {
	cros_enable_cxx_exceptions
	cmake-utils_src_configure
}

src_install() {
	local OUTDIR="${WORKDIR}/spirv-cross-${PV}_build"

	dobin "${OUTDIR}/spirv-cross"
}
