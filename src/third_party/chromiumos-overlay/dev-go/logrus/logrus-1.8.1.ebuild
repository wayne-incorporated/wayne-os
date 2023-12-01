# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/sirupsen/logrus v${PV}"

CROS_GO_PACKAGES=(
	"github.com/sirupsen/logrus"
)

inherit cros-go

DESCRIPTION="Logrus is a structured logger for Go (golang), completely API compatible with the standard library logger."
HOMEPAGE="https://github.com/sirupsen/logrus"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND="
	dev-go/go-spew
	dev-go/go-sys
	dev-go/testify
"
RDEPEND="!<=dev-go/docker-20.10.8-r1"
