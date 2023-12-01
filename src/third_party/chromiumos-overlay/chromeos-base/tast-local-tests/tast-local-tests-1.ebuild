# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="All Tast local test bundles"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/tast/"

LICENSE="Apache-2.0 BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	chromeos-base/tast-local-tests-cros
	virtual/tast-local-tests
"
DEPEND="${RDEPEND}"
