# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/inconshreveable/mousetrap v${PV}"

CROS_GO_PACKAGES=(
	"github.com/inconshreveable/mousetrap"
)

inherit cros-go

DESCRIPTION="mousetrap is a tiny library that answers a single question.

On a Windows machine, was the process invoked by someone double clicking on the executable file while browsing in explorer?"
HOMEPAGE="https://github.com/inconshreveable/mousetrap"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
