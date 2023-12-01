# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_GO_SOURCE="github.com/catapult-project/catapult 35457f076227dce062ece5b51f3655223af1788f"

CROS_GO_BINARIES=(
	"github.com/catapult-project/catapult/web_page_replay_go/src/wpr.go"
)

CROS_GO_TEST=(
	"github.com/catapult-project/catapult/web_page_replay_go/src/webpagereplay"
)

inherit cros-go
SRC_URI="$(cros-go_src_uri)"

DESCRIPTION="Web Page Replay (for testing)"
HOMEPAGE="https://github.com/catapult-project/catapult/tree/master/web_page_replay_go"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND=""
DEPEND="${RDEPEND}
	dev-go/cli
	dev-go/net
	dev-go/go-md2man
	dev-go/blackfriday"

src_install() {
	cros-go_src_install
	local wprg_src="${S}/src/github.com/catapult-project/catapult/web_page_replay_go"
	insinto "/usr/share/wpr"
	doins "${wprg_src}/wpr_cert.pem"
	doins "${wprg_src}/wpr_key.pem"
	doins "${wprg_src}/deterministic.js"
}
