# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="9214eeb399db2148a35ea5f28b2637df6cac94c6"
CROS_WORKON_TREE="2761b7b0568a71ed712ef691976b96dae3b8b2aa"
CROS_WORKON_LOCALNAME="platform/vkbench"
CROS_WORKON_PROJECT="chromiumos/platform/vkbench"

inherit cros-workon cmake-utils

DESCRIPTION="Microbenchmark for vulkan"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/vkbench/"
SRC_URI=""

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="vulkan"

REQUIRED_USE="vulkan"

BDEPEND="
	dev-util/glslang
"

RDEPEND="
	dev-libs/libfmt:=
	media-libs/libpng:=
	media-libs/vulkan-loader:=
	virtual/vulkan-icd:=
"
DEPEND="${RDEPEND}
	dev-util/vulkan-headers"
