# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/sunfish-shogi/bufseekio e5e41a4a1c4c3aa91b37213834257b960f1aed9c"

CROS_GO_PACKAGES=(
	"github.com/sunfish-shogi/bufseekio/..."
)

inherit cros-go

DESCRIPTION="Go library for providing buffered I/O with io.Seeker interface."
HOMEPAGE="https://github.com/sunfish-shogi/bufseekio"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/testify"
RDEPEND=""
