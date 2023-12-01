# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/gonum/gonum:gonum.org/v1/gonum v${PV}"

CROS_GO_PACKAGES=(
	"gonum.org/v1/gonum/blas"
	"gonum.org/v1/gonum/blas/blas32"
	"gonum.org/v1/gonum/blas/blas64"
	"gonum.org/v1/gonum/blas/cblas128"
	"gonum.org/v1/gonum/blas/cblas64"
	"gonum.org/v1/gonum/blas/gonum"
	"gonum.org/v1/gonum/internal/asm/..."
	"gonum.org/v1/gonum/internal/cmplx64"
	"gonum.org/v1/gonum/internal/math32"
	"gonum.org/v1/gonum/floats/..."
	"gonum.org/v1/gonum/lapack"
	"gonum.org/v1/gonum/lapack/gonum"
	"gonum.org/v1/gonum/lapack/lapack64"
	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/dsp/fourier"
	"gonum.org/v1/gonum/dsp/fourier/internal/fftpack"
)

CROS_GO_TEST=(
	"gonum.org/v1/gonum"
)

inherit cros-go

DESCRIPTION="The core packages of the Gonum suite are written in pure Go with some assembly."
HOMEPAGE="https://www.gonum.org/"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/go-tools
	dev-go/golang-freetype
	dev-go/svgo
"

RDEPEND=""
