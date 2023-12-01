# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

# Use latest in Go 1.15 branch
# 1a77d5e9f316d6917d88a497ab4db07399cbc923 (HEAD, origin/release-branch.go1.15)
CROS_GO_SOURCE="github.com/golang/xerrors:golang.org/x/xerrors 1a77d5e9f316d6917d88a497ab4db07399cbc923"

CROS_GO_PACKAGES=(
	"golang.org/x/xerrors"
	"golang.org/x/xerrors/internal"
)

inherit cros-go

DESCRIPTION="This package supports transitioning to the Go 2 proposal for error values."
HOMEPAGE="https://github.com/golang/xerrors"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
