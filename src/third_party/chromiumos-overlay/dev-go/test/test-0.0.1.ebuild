# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"github.com/chzyer/test a1ea475d72b168a29f44221e0ad031a842642302"
)

CROS_GO_PACKAGES=(
	"github.com/chzyer/test"
)

inherit cros-go

DESCRIPTION="Small disk testing package"
HOMEPAGE="https://github.com/chzyer/test"
SRC_URI="$(cros-go_src_uri)"
RESTRICT="binchecks strip"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"

DEPEND="dev-go/logex"
RDEPEND=""
