# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/golang/glog v${PV}"

CROS_GO_PACKAGES=(
	"github.com/golang/glog"
)

inherit cros-go

DESCRIPTION="Leveled execution logs for Go"
HOMEPAGE="https://github.com/golang/glog"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
