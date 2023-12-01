# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/kr/fs v${PV}"

CROS_GO_PACKAGES=(
	"github.com/kr/fs"
)

inherit cros-go

DESCRIPTION="Package fs provides filesystem-related functions."
HOMEPAGE="https://github.com/kr/fs"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
