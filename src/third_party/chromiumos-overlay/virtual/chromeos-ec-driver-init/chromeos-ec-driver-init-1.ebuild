# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Generic ebuild which satisfies virtual/chromeos-ec-driver
This is a direct dependency of chromeos-base/iioservice,
and it is overridden in private overlay to load cros-ec stack for special ECs."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/ec/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
