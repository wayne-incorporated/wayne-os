# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/mdlayher/netlink 336c8d74f4a037ab2e19a7b95dc2189673095121"

CROS_GO_PACKAGES=(
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

inherit cros-go

DESCRIPTION="Package netlink provides low-level access to Linux netlink sockets"
HOMEPAGE="https://github.com/mdlayher/netlink"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-sys
	dev-go/net
"
RDEPEND=""
