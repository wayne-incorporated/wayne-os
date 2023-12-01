# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/term:golang.org/x/term 03fcf44c2211dcd5eb77510b5f7c1fb02d6ded50"

CROS_GO_PACKAGES=(
	"golang.org/x/term"
)

inherit cros-go

DESCRIPTION="Go terminal and console support"
HOMEPAGE="https://golang.org/x/term"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/go-sys"
RDEPEND=""
