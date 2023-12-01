# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/4lon/crc8 v${PV}"

CROS_GO_PACKAGES=(
	"github.com/4lon/crc8"
)

inherit cros-go

DESCRIPTION="Go implementation of CRC-8 calculation for majority of widely-used polinomials."
HOMEPAGE="github.com/4lon/crc8"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
