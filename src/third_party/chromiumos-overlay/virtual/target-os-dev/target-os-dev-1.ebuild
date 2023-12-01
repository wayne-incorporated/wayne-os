# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of additional packages for the developer OS image;
by default, we build a Chromium OS dev image.
Note: When building a dev image, the build system pulls in all packages from the
base image as well."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="virtual/target-chromium-os-dev"
