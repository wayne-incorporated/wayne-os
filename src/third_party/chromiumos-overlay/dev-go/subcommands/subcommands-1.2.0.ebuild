# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/google/subcommands v${PV}"

CROS_GO_PACKAGES=(
	"github.com/google/subcommands"
)

inherit cros-go

DESCRIPTION="Go subcommand library"
HOMEPAGE="https://github.com/google/subcommands"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
