# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/pixelbender/go-matroska 4ea028a99fa677aba6359303ce619ad7d6d9ee57"

CROS_GO_PACKAGES=(
	"github.com/pixelbender/go-matroska/..."
)

inherit cros-go

DESCRIPTION="Golang implementation of Matroska and WebM media container formats"
HOMEPAGE="https://github.com/pixelbender/go-matroska"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
