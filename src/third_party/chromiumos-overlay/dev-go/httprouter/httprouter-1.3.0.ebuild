# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/julienschmidt/httprouter v${PV}"

CROS_GO_PACKAGES=(
	"github.com/julienschmidt/httprouter"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="A high performance HTTP request router that scales well"
HOMEPAGE="https://github.com/julienschmidt/httprouter"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="!<app-emulation/lxd-3.0.0-r4"
RDEPEND="${DEPEND}"
