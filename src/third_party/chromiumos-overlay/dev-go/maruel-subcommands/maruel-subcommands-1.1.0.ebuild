# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"github.com/maruel/subcommands v${PV}"
)

CROS_GO_PACKAGES=(
	"github.com/maruel/subcommands"
)

inherit cros-go

DESCRIPTION="Go subcommand library"
HOMEPAGE="https://github.com/maruel/subcommands"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/levenshtein
	dev-go/kr-text
	dev-go/pretty
	dev-go/utiltest
"
RDEPEND="${DEPEND}"
