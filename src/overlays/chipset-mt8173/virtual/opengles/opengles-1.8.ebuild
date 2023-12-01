# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Virtual for OpenGLES implementations"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
	virtual/img-ddk
	media-libs/mesa-img
"
RDEPEND="${DEPEND}"
