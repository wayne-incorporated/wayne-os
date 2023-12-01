# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/stretchr/objx v${PV}"

CROS_GO_PACKAGES=(
	"github.com/stretchr/objx"
)

inherit cros-go

DESCRIPTION="Go package for dealing with maps, slices, JSON and other data."
HOMEPAGE="https://github.com/stretchr/objx"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="dev-go/go-spew"
RDEPEND=""
