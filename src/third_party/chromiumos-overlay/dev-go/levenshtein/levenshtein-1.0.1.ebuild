# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE=(
	"github.com/texttheater/golang-levenshtein v${PV}"
)

CROS_GO_PACKAGES=(
	"github.com/texttheater/golang-levenshtein/levenshtein"
)

inherit cros-go

DESCRIPTION="Go subcommand library"
HOMEPAGE="https://github.com/texttheater/golang-levenshtein/levenshtein"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND="${DEPEND}"
