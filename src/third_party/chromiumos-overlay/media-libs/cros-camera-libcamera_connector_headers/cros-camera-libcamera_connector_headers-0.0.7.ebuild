# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Installs header files for cros-camera-libcamera_connector."
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.gz"

LICENSE="LICENSE.parallels"
SLOT="0"
KEYWORDS="*"
IUSE=""
S="${WORKDIR}/${PN}"
# Versions before r62 install camera_service_connector.h, which causes a file
# conflict with this package.
RDEPEND="!<media-libs/cros-camera-libcamera_connector-0.0.1-r62"

src_install() {
	insinto "/usr/include/cros-camera"
	doins "camera_service_connector.h"
}

