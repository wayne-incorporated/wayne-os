# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"github.com/maruel/ut v${PV}"
)

CROS_GO_PACKAGES=(
	"github.com/maruel/ut"
)

inherit cros-go

DESCRIPTION="Compact testing utilities to shorten Go unit tests."
HOMEPAGE="https://github.com/maruel/ut"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-difflib
	dev-go/pretty

"
RDEPEND="${DEPEND}"
