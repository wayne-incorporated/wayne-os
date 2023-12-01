# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon

DESCRIPTION="List of packages that are needed inside the Chromium OS base (release)"
HOMEPAGE="https://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="~*"
IUSE=""

# baselayout gives us the base filesystem layout, which isn't worth reproducing.
RDEPEND="sys-apps/baselayout"

# The rest of the things for the board itself.
RDEPEND="
	${RDEPEND}
	chromeos-base/size-test
"
DEPEND=""
