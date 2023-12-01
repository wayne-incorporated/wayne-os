# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_GO_SOURCE="github.com/dominikh/go-tools:honnef.co/go/tools v${PV}"

CROS_GO_BINARIES=(
	"honnef.co/go/tools/cmd/staticcheck"
	"honnef.co/go/tools/cmd/structlayout-optimize"
	"honnef.co/go/tools/cmd/structlayout-pretty"
	"honnef.co/go/tools/cmd/keyify"
)

inherit cros-go

DESCRIPTION="Staticcheck is a state of the art linter for the Go programming language."
HOMEPAGE="https://github.com/dominikh/go-tools"
SRC_URI="$(cros-go_src_uri)"


LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-tools
	dev-go/mod
	dev-go/toml
	dev-go/xerrors
"
RDEPEND="${DEPEND}"
