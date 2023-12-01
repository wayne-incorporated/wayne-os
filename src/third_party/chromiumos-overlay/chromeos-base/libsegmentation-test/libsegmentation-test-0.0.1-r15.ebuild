# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "9d663502e2c54745e6e14054da5eaf7e485ec0a7" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk libsegmentation .gn"

PLATFORM_SUBDIR="libsegmentation/tools"

inherit cros-workon platform

DESCRIPTION="Test for Library to get ChromiumOS system properties"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libsegmentation"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="feature_management"

RDEPEND="
	chromeos-base/libsegmentation:=
"

DEPEND="${RDEPEND}"
