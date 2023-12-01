# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

LICENSE="metapackage"

DESCRIPTION="Virtual for ARC OpenGLES implementations"
SRC_URI=""

SLOT="0"
KEYWORDS="-* arm64 arm"

DEPEND="media-libs/arc-mesa-freedreno"
RDEPEND="${DEPEND}"
