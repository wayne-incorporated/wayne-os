# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/stretchr/testify v${PV}"

CROS_GO_PACKAGES=(
	"github.com/stretchr/testify/..."
)

inherit cros-go

DESCRIPTION="Go code (golang) set of packages that provide many tools for testifying that your code will behave as you intend."
HOMEPAGE="https://github.com/stretchr/testify"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="
	dev-go/go-spew
	dev-go/go-difflib
	dev-go/objx
	dev-go/yaml:3
"
RDEPEND=""
