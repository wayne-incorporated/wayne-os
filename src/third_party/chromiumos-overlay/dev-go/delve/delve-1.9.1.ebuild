# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/go-delve/delve v${PV}"

CROS_GO_BINARIES=(
	"github.com/go-delve/delve/cmd/dlv"
)

inherit cros-go

DESCRIPTION="A debugger for the go programming language."
HOMEPAGE="https://github.com/go-delve/delve"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
# Delve doesn't support arm32 boards yet (github.com/go-delve/delve/issues/2051)
KEYWORDS="-* x86 amd64 arm64"
IUSE=""
RESTRICT="strip"
