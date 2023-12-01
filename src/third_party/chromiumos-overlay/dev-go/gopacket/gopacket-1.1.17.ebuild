# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/google/gopacket v${PV}"

CROS_GO_PACKAGES=(
	"github.com/google/gopacket/..."
)

inherit cros-go

DESCRIPTION="Provides packet processing capabilities for Go"
HOMEPAGE="https://github.com/google/gopacket"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-sys
	dev-go/net
"
RDEPEND=""
