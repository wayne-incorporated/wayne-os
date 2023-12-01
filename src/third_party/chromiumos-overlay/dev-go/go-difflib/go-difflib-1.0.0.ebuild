# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/pmezard/go-difflib v${PV}"

CROS_GO_PACKAGES=(
	"github.com/pmezard/go-difflib/difflib"
)

inherit cros-go

DESCRIPTION="Go-difflib is a partial port of python 3 difflib package."
HOMEPAGE="https://github.com/pmezard/go-difflib"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
