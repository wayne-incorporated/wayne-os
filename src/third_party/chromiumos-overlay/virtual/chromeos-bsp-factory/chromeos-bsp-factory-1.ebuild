# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Generic ebuild which satisifies virtual/chromeos-bsp-factory.
This is a direct dependency of chromeos-base/factory, but is expected
to be overridden in an overlay for each specialized board.  A typical
non-generic implementation will install any board-specific configuration
files and drivers which are not suitable for inclusion in a generic board
overlay."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="|| (
	chromeos-base/factory-board
	chromeos-base/chromeos-factory-board
	)
	chromeos-base/factory-baseboard"

DEPEND="${RDEPEND}"
