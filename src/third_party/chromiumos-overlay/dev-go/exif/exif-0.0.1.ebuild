# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/rwcarlsen/goexif 9e8deecbddbd4989a3e8d003684b783412b41e7a"

CROS_GO_PACKAGES=(
	"github.com/rwcarlsen/goexif/..."
)

inherit cros-go

DESCRIPTION="Go library for reading EXIF from JPEG"
HOMEPAGE="https://github.com/rwcarlsen/goexif"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
