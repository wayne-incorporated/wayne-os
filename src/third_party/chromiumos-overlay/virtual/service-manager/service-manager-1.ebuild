# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Generic ebuild which satisifies virtual/service-manager.
This is a direct dependency of chromeos-base/chromeos, but can
be overridden in an overlay for specialized boards.

To satisfy this virtual, a package should cause to be installed everything
required to bring the system up and start managing system services."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="chromeos-base/chromeos-init"
DEPEND="${RDEPEND}"
