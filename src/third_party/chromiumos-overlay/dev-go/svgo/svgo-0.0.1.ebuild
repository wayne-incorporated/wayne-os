# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/ajstarks/svgo go.weekly.2012-01-27"

CROS_GO_PACKAGES=(
	"github.com/ajstarks/svgo/..."
)

CROS_GO_TEST=(
	"github.com/ajstarks/svgo"
)

inherit cros-go

DESCRIPTION="A Go library for SVG generation"
HOMEPAGE="https://github.com/ajstarks/svgo"
SRC_URI="$(cros-go_src_uri)"

LICENSE="CC-BY-SA-3.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
