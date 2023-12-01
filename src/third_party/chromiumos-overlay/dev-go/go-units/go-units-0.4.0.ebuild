# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/docker/go-units v${PV}"

CROS_GO_PACKAGES=(
	"github.com/docker/go-units"
)

inherit cros-go

DESCRIPTION="Parse and print size and time units in human-readable format."
HOMEPAGE="https://github.com/docker/go-units"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND=""
RDEPEND="!<=dev-go/docker-20.10.8-r1"
