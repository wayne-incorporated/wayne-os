# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/tklauser/go-sysconf v${PV}"

CROS_GO_PACKAGES=(
	"github.com/tklauser/go-sysconf"
)

CROS_GO_TEST=(
	"github.com/tklauser/go-sysconf"
)

inherit cros-go

DESCRIPTION="sysconf for Go, without using cgo or external binaries (e.g. getconf)."
HOMEPAGE="https://github.com/tklauser/go-sysconf"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="
	dev-go/numcpus
	dev-go/go-sys
"
RDEPEND="${DEPEND}"
