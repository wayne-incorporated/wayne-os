# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"github.com/hashicorp/mdns v${PV}"
)

CROS_GO_PACKAGES=(
	"github.com/hashicorp/mdns"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Simple mDNS client/server library in Golang"
HOMEPAGE="https://github.com/hashicorp/mdns"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/dns
	dev-go/net
"
RDEPEND="${DEPEND}"
