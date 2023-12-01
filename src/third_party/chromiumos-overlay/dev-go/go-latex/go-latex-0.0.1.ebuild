# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/go-latex/latex fdd06906368d258859329d1a962a071ea194800b"

CROS_GO_PACKAGES=(
	"github.com/go-latex/latex"
	"github.com/go-latex/latex/ast"
	"github.com/go-latex/latex/drawtex"
	"github.com/go-latex/latex/font"
	"github.com/go-latex/latex/font/ttf"
	"github.com/go-latex/latex/internal/tex2unicode"
	"github.com/go-latex/latex/mtex"
	"github.com/go-latex/latex/mtex/symbols"
	"github.com/go-latex/latex/tex"
	"github.com/go-latex/latex/token"
)

inherit cros-go

DESCRIPTION="Go package for LaTeX"
HOMEPAGE="https://github.com/go-latex/latex"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-fonts-liberation
	dev-go/go-image
	dev-go/gofpdf
	dev-go/fogleman-gg
"
RDEPEND=""
