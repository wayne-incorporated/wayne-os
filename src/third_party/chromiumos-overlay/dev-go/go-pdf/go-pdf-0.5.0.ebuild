# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/go-pdf/fpdf v0.5.0"

CROS_GO_PACKAGES=(
	"github.com/go-pdf/fpdf"
	"github.com/go-pdf/fpdf/internal/..."
	"github.com/go-pdf/fpdf/list"
	"github.com/go-pdf/fpdf/contrib/gofpdi"
)

inherit cros-go

DESCRIPTION="A PDF document generator with high level support for text, drawing and images"
HOMEPAGE="https://github.com/go-pdf/fpdf"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-image
	dev-go/gofpdi
"
RDEPEND=""
