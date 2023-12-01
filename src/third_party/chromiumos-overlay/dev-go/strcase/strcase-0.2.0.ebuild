# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/iancoleman/strcase v${PV}"

CROS_GO_PACKAGES=(
	"github.com/iancoleman/strcase"
)

inherit cros-go

DESCRIPTION="strcase is a go package for converting string case to various cases"
HOMEPAGE="https://github.com/iancoleman/strcase"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
