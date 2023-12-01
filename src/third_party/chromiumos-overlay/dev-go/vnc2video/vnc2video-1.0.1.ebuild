# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/matts1/vnc2video v${PV}"

CROS_GO_PACKAGES=(
	"github.com/matts1/vnc2video"
	"github.com/matts1/vnc2video/encoders"
	"github.com/matts1/vnc2video/logger"
)

inherit cros-go

DESCRIPTION="A fork of vnc2video allowing lazy encoding of video."
HOMEPAGE="https://github.com/matts1/vnc2video"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
