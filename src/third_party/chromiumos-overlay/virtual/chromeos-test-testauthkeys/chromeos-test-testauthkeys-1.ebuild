# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Generic ebuild that satisifies virtual/chromeos-test-testauthkeys.
This is a direct dependency of chromeos-base/chromeos-test-testauthkeys, but is
expected to be overridden in an overlay for some specialized board."
HOMEPAGE="http://www.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

RDEPEND="chromeos-base/chromeos-test-testauthkeys"
