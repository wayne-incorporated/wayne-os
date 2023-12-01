# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Generic ebuild which satisfies virtual/chromeos-bsp-dev-root.
This is a direct dependency of chromeos-base/chromeos-dev-root, but is expected
to be overridden in an overlay for each specialized board.  A typical
non-generic implementation will install any board-specific developer only files
and executables which are not suitable for inclusion on the root partition in a
generic board overlay."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""
