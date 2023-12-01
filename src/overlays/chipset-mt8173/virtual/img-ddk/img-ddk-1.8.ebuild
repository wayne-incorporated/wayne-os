# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Virtual for img-ddk packages (source or prebuilt binaries)"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

DEPEND="
	media-libs/img-ddk-bin
"
RDEPEND="${DEPEND}"
