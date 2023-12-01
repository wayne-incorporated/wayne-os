# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/fogleman/gg v1.3.0"

CROS_GO_PACKAGES=(
	"github.com/fogleman/gg"
)

CROS_GO_TEST=(
	"github.com/fogleman/gg"
)

inherit cros-go

DESCRIPTION="Go Graphics - 2D rendering in Go with a simple API"
HOMEPAGE="https://github.com/fogleman/gg"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/golang-freetype"
RDEPEND=""
