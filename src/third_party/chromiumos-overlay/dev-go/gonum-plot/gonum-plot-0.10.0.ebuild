# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/gonum/plot:gonum.org/v1/plot v${PV}"

# Skip dep failures due to liberation font and latex which are not used
CROS_GO_SKIP_DEP_CHECK="1"

CROS_GO_PACKAGES=(
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/font"
	"gonum.org/v1/plot/font/liberation"
	"gonum.org/v1/plot/palette"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/text"
	"gonum.org/v1/plot/tools/..."
	"gonum.org/v1/plot/vg/..."
)

CROS_GO_TEST=(
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/cmpimg"
)

inherit cros-go

DESCRIPTION="Provides an API for setting up plots, and primitives for drawing on plots"
HOMEPAGE="https://www.gonum.org/"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-image
	dev-go/go-fonts-liberation
	dev-go/go-latex
	dev-go/gonum
	dev-go/golang-freetype
	dev-go/fogleman-gg
	dev-go/rsc-io-pdf
	dev-go/svgo
"

RDEPEND=""
