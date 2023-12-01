# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Virtual for OpenGLES implementations"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
	media-libs/mali-drivers-bin
	x11-drivers/opengles-headers
"
RDEPEND="${DEPEND}"
