# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/dave/dst v${PV}"

CROS_GO_PACKAGES=(
	"github.com/dave/dst/..."
)

inherit cros-go

DESCRIPTION="Decorated Syntax Tree"
HOMEPAGE="https://github.com/dave/dst"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/crypto
	dev-go/demangle
	dev-go/go-arch
	dev-go/go-billy
	dev-go/go-diff
	dev-go/go-tools
	dev-go/jennifer
	dev-go/pprof
"
RDEPEND="${DEPEND}"
