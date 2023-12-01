# Copyright 2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_GO_SOURCE="github.com/blackjack/webcam v${PV}"

CROS_GO_PACKAGES=(
	"github.com/blackjack/webcam"
	"github.com/blackjack/webcam/ioctl"
)

inherit cros-go

DESCRIPTION="This is a go library for working with webcams and other video capturing devices."
HOMEPAGE="https://github.com/blackjack/webcam"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/go-sys"
RDEPEND=""
