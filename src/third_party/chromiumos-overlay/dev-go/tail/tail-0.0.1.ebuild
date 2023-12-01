# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/nxadm/tail abad231d8d07ef91e09cd4c4c457cac35ed3bbb9"

CROS_GO_PACKAGES=(
	"github.com/nxadm/tail/..."
)

inherit cros-go

DESCRIPTION="Library that emulates the features of the BSD tail program"
HOMEPAGE="https://github.com/nxadm/tail"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/fsnotify
	dev-go/tomb
"
RDEPEND=""
