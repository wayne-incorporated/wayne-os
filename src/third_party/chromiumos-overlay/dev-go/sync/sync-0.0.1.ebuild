# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/sync:golang.org/x/sync 036812b2e83c0ddf193dd5a34e034151da389d09"

CROS_GO_PACKAGES=(
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="Additional Go concurrency primitives"
HOMEPAGE="https://golang.org/x/sync"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND="dev-go/net"
