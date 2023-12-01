# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/creack/pty v1.1.9"

CROS_GO_PACKAGES=(
	"github.com/creack/pty"
)

inherit cros-go

DESCRIPTION="Pty is a Go package for using unix pseudo-terminals."
HOMEPAGE="https://github.com/creack/pty"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
