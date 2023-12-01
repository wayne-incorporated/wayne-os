# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="Meta ebuild for all packages providing tests"
HOMEPAGE="http://www.chromium.org"

LICENSE="GPL-2"
SLOT=0
KEYWORDS="~*"
IUSE=""

RDEPEND=""
DEPEND=""
