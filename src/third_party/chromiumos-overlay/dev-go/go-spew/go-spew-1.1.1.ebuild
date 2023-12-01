# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/davecgh/go-spew v${PV}"

CROS_GO_PACKAGES=(
	"github.com/davecgh/go-spew/spew"
)

inherit cros-go

DESCRIPTION="Go-spew implements a deep pretty printer for Go data structures to aid in debugging."
HOMEPAGE="https://github.com/davecgh/go-spew"
SRC_URI="$(cros-go_src_uri)"

LICENSE="ISC"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
