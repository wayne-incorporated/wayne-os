# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/gorilla/websocket v${PV}"

CROS_GO_PACKAGES=(
	"github.com/gorilla/websocket"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="A WebSocket implementation for Go"
HOMEPAGE="https://github.com/gorilla/websocket"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-2"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
