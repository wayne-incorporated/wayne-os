# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/russross/blackfriday:github.com/russross/blackfriday/v2 v${PV}"

CROS_GO_PACKAGES=(
	"github.com/russross/blackfriday/v2"
)

inherit cros-go

DESCRIPTION="Blackfriday is a Markdown processor implemented in Go."
HOMEPAGE="https://github.com/russross/blackfriday"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
