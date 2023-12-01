# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/sergi/go-diff v${PV}"

CROS_GO_PACKAGES=(
	"github.com/sergi/go-diff/diffmatchpatch"
)

inherit cros-go

DESCRIPTION="go-diff offers algorithms to perform operations required for synchronizing plain text"
HOMEPAGE="https://github.com/sergi/go-diff"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-spew
	dev-go/pretty
	dev-go/testify
	dev-go/check
	dev-go/yaml:0
"
RDEPEND=""
