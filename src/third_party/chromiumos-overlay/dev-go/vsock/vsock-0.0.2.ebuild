# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/mdlayher/vsock 9de589a8c10bfadb0e94fe67caa79a05a1a45a52"

CROS_GO_PACKAGES=(
	"github.com/mdlayher/vsock"
)

inherit cros-go

DESCRIPTION="Package for using AF_VSOCK in Go"
HOMEPAGE="https://github.com/mdlayher/vsock"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/go-sys
	dev-go/net
"
RDEPEND=""
