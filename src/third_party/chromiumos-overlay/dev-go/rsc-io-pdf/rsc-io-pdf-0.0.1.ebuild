# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/rsc/pdf:rsc.io/pdf v0.1.1"

CROS_GO_PACKAGES=(
	"rsc.io/pdf"
)

inherit cros-go

DESCRIPTION="Package pdf implements reading of PDF files."
HOMEPAGE="https://pkg.go.dev/rsc.io/pdf"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
