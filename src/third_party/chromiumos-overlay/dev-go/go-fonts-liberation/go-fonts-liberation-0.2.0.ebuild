# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/go-fonts/liberation v${PV}"

CROS_GO_PACKAGES=(
	"github.com/go-fonts/liberation/..."
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Liberation fonts for Go"
HOMEPAGE="https://github.com/go-fonts/liberation"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/go-image"
RDEPEND=""
