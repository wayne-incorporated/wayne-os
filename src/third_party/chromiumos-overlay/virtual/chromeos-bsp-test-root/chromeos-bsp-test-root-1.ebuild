# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Generic ebuild which satisfies virtual/chromeos-bsp-test-root.
This package is merged onto the rootfs when an image is modified for test.  A
typical non-generic implementation will install any board-specific test-only
files which are required on the rootfs (such as upstart jobs) but which are not
suitable for inclusion in a generic board overlay."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""
