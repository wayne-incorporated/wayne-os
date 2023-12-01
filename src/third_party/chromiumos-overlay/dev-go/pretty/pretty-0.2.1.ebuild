# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/kr/pretty v0.2.1"

CROS_GO_PACKAGES=(
	"github.com/kr/pretty"
)

inherit cros-go

DESCRIPTION="Package pretty provides pretty-printing for Go values."
HOMEPAGE="https://github.com/kr/pretty"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/kr-text"
RDEPEND=""
