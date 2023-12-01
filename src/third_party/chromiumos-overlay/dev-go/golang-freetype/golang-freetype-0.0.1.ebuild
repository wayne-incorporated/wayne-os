# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/golang/freetype bcfeb16b74e8aea9e2fe043406f2ef74b1cb0759"

CROS_GO_PACKAGES=(
	"github.com/golang/freetype"
	"github.com/golang/freetype/raster"
	"github.com/golang/freetype/truetype"
)

CROS_GO_TEST=(
	"github.com/golang/freetype"
)

inherit cros-go

DESCRIPTION="Freetype font rasterizer in the Go programming language"
HOMEPAGE="https://github.com/golang/freetype"
SRC_URI="$(cros-go_src_uri)"

LICENSE="FTL"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/go-image"
RDEPEND=""
