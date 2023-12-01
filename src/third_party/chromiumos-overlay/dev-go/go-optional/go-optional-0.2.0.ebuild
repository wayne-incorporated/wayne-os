# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_GO_SOURCE="github.com/leighmcculloch/go-optional v${PV}"

CROS_GO_PACKAGES=(
	"github.com/leighmcculloch/go-optional"
)

inherit cros-go

DESCRIPTION="Package optional exports an Optional[T] type that can wrap any type to represent the lack of value."
HOMEPAGE="https://github.com/leighmcculloch/go-optional"
SRC_URI="$(cros-go_src_uri)"


LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"
