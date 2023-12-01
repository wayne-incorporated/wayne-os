# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/go-check/check:gopkg.in/check.v1 10cb98267c6cb43ea9cd6793f29ff4089c306974"

CROS_GO_PACKAGES=(
	"gopkg.in/check.v1"
)

inherit cros-go

DESCRIPTION="Rich testing for the Go language"
HOMEPAGE="https://gopkg.in/check.v1"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/pretty"
RDEPEND=""
