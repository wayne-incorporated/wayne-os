# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/google/pprof 513e8ac6eea103037e9be150bd17ceccacbe7bf6"

CROS_GO_PACKAGES=(
	"github.com/google/pprof/driver"
	"github.com/google/pprof/internal/..."
	"github.com/google/pprof/profile"
	"github.com/google/pprof/third_party/..."
)

CROS_GO_BINARIES=(
	"github.com/google/pprof/pprof.go"
)

inherit cros-go

DESCRIPTION="pprof is a tool for visualization and analysis of profiling data "
HOMEPAGE="https://github.com/google/pprof"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/demangle
	dev-go/logex
	dev-go/readline
	dev-go/test
	dev-go/go-sys
"
RDEPEND=""
