# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7


CROS_GO_SOURCE="github.com/tarm/serial 98f6abe2eb07edd42f6dfa2a934aea469acc29b7"

CROS_GO_PACKAGES=(
	"github.com/tarm/serial"
)

inherit cros-go

DESCRIPTION="Go package to read and write serial port byte streams"
HOMEPAGE="https://github.com/tarm/serial"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND="dev-go/go-sys"
RDEPEND=""
