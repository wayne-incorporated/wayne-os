# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/kr/text v${PV}"

CROS_GO_PACKAGES=(
	"github.com/kr/text"
)

inherit cros-go

DESCRIPTION="Go package for manipulating paragraphs of text."
HOMEPAGE="https://github.com/kr/text"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/pty"
RDEPEND=""
