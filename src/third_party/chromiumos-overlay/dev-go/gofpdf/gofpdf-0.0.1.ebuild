# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/jung-kurt/gofpdf v2.17.2"

CROS_GO_PACKAGES=(
	"github.com/jung-kurt/gofpdf/..."
)

CROS_GO_TEST=(
	"github.com/jung-kurt/gofpdf"
)

inherit cros-go

DESCRIPTION="A PDF document generator with high level support for text, drawing and images"
HOMEPAGE="https://go.googlesource.com/image"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
