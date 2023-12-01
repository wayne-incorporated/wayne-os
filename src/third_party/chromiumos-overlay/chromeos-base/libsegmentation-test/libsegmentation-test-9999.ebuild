# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk libsegmentation .gn"

PLATFORM_SUBDIR="libsegmentation/tools"

inherit cros-workon platform

DESCRIPTION="Test for Library to get ChromiumOS system properties"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libsegmentation"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="feature_management"

RDEPEND="
	chromeos-base/libsegmentation:=
"

DEPEND="${RDEPEND}"
