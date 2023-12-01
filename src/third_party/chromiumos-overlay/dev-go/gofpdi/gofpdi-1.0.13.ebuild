# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/phpdave11/gofpdi v${PV}"

CROS_GO_PACKAGES=(
	"github.com/phpdave11/gofpdi/..."
)

inherit cros-go

DESCRIPTION="Go Free PDF Document Importer"
HOMEPAGE="https://github.com/phpdave11/gofpdi"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
