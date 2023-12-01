# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/chzyer/logex v${PV}"

CROS_GO_PACKAGES=(
	"github.com/chzyer/logex"
)

inherit cros-go

DESCRIPTION="An golang log lib, supports tracing and level, wrap by standard log lib."
HOMEPAGE="https://github.com/chzyer/logex"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
