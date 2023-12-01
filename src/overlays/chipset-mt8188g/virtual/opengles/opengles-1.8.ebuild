# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="Virtual for OpenGLES implementations"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="video_cards_panfrost"

DEPEND="
	video_cards_panfrost? ( media-libs/mesa-panfrost )
	!video_cards_panfrost? (
		media-libs/mali-drivers-valhall-bin
		x11-drivers/opengles-headers
	)
"
RDEPEND="${DEPEND}"
BDEPEND=""
