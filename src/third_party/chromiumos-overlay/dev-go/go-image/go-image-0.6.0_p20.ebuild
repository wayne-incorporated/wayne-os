# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/image:golang.org/x/image a66eb6448b8d7557efb0c974c8d4d72085371c58"

CROS_GO_PACKAGES=(
	"golang.org/x/image/..."
	"golang.org/x/image/font/opentype"
)

CROS_GO_TEST=(
	"golang.org/x/image"
)

inherit cros-go

DESCRIPTION="Go packages for image libraries"
HOMEPAGE="https://go.googlesource.com/image"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/text"
RDEPEND=""
