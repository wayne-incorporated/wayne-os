# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/bugst/go-serial:go.bug.st/serial v${PV}"

CROS_GO_PACKAGES=(
	"go.bug.st/serial"
	"go.bug.st/serial/unixutils"
	"go.bug.st/serial/portlist"
	"go.bug.st/serial/enumerator"
)

inherit cros-go

DESCRIPTION="A cross-platform serial library for go-lang."
HOMEPAGE="https://github.com/bugst/go-serial"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/goselect
	dev-go/go-sys
"
RDEPEND=""
