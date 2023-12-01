# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/tklauser/numcpus v${PV}"

CROS_GO_PACKAGES=(
	"github.com/tklauser/numcpus"
)

CROS_GO_TEST=(
	"github.com/tklauser/numcpus"
)

inherit cros-go

DESCRIPTION="Provides information about the number of CPU."
HOMEPAGE="https://github.com/tklauser/numcpus"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-sys
"
RDEPEND="${DEPEND}"
