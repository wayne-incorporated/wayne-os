# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Packages for Termina test images"
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	chromeos-base/chromeos-test-root
	chromeos-base/graphics-utils-python
	dev-python/protobuf-python
	sys-apps/net-tools
	sys-apps/pciutils
	sys-apps/usbutils
"
