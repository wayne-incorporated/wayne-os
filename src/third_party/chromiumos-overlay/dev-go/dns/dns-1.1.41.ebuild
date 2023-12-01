# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/miekg/dns v${PV}"

CROS_GO_PACKAGES=(
	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="DNS library in Go"
HOMEPAGE="https://github.com/miekg/dns"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/crypto
	dev-go/go-sys
	dev-go/net
	dev-go/sync
"
RDEPEND="${DEPEND}"
