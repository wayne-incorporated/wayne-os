# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/pkg/errors v${PV}"

CROS_GO_PACKAGES=(
	"github.com/pkg/errors"
)

inherit cros-go

DESCRIPTION="Error handling primitives for Go."
HOMEPAGE="https://github.com/pkg/errors"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
