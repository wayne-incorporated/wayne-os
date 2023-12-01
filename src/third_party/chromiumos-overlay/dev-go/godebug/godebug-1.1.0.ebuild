# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI="7"

CROS_GO_SOURCE="github.com/kylelemons/godebug v${PV}"

CROS_GO_PACKAGES=(
	"github.com/kylelemons/godebug/..."
)

inherit cros-go

DESCRIPTION="Debugging helper utilities for Go"
HOMEPAGE="https://github.com/kylelemons/godebug"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
