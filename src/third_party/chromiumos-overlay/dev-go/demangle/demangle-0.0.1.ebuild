# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/ianlancetaylor/demangle b7f99f1dbc9644095cd3254251eccb314d1a81f7"

CROS_GO_PACKAGES=(
	"github.com/ianlancetaylor/demangle"
)

inherit cros-go

DESCRIPTION="C++ symbol name demangler written in Go "
HOMEPAGE="https://github.com/ianlancetaylor/demangle"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
