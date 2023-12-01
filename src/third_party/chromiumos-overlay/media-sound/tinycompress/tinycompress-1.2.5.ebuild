# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="The APIs to open a ALSA compressed device and read/write compressed data to it."
HOMEPAGE="https://github.com/alsa-project/tinycompress"
SRC_URI="https://www.alsa-project.org/files/pub/tinycompress/${P}.tar.bz2"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="*"

RDEPEND="media-video/libva-utils"
