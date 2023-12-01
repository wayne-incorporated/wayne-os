# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/dave/jennifer v${PV}"

CROS_GO_PACKAGES=(
	"github.com/dave/jennifer/..."
)

inherit cros-go

DESCRIPTION="Jennifer is a code generator for Go"
HOMEPAGE="https://github.com/dave/jennifer"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND="${DEPEND}"
