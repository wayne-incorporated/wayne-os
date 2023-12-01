# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of additional packages for the test OS image;
by default, we build a Chromium OS test image.
Note: When building a test image, the build system pulls in all packages from
the dev image (and by extension the base image) as well."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="virtual/target-chromium-os-test"
