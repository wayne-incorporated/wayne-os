# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="All Tast remote test bundles"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/tast/"

LICENSE="Apache-2.0 BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	chromeos-base/tast-remote-tests-cros
	virtual/tast-remote-tests
"
DEPEND="${RDEPEND}"
