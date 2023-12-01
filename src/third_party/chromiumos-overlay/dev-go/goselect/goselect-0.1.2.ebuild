# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/creack/goselect v${PV}"

CROS_GO_PACKAGES=(
	"github.com/creack/goselect"
)

inherit cros-go

DESCRIPTION="select(2) implementation in Go"
HOMEPAGE="https://github.com/creack/goselect"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
